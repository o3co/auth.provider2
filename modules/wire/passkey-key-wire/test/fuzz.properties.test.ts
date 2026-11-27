import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { passkeyThumbprintInput } from "../src/contract.ts";

// C9: the reader of a passkey's public key the screen sends, and what its thumbprint covers.
const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261127);
const numRuns = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Bytes in their one unpadded base64url spelling, written apart from the wire's: as many as asked. */
const spells = (text: unknown, length: (n: number) => boolean) => {
	if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) return false;
	const bytes = Buffer.from(text, "base64url");
	return bytes.toString("base64url") === text && length(bytes.length);
};
/** An RSA modulus as the wire reads one: 2048 to 4096 bits, no leading zero byte, odd. */
const modulus = (text: unknown) =>
	spells(text, (n) => n >= 256 && n <= 512) &&
	((bytes) =>
		(bytes[0] ?? 0) !== 0 &&
		(bytes.length > 256 || (bytes[0] ?? 0) >= 0x80) &&
		((bytes.at(-1) ?? 0) & 1) === 1)(Buffer.from(text as string, "base64url"));
/** The reference's reading: the RFC 7638 input a passkey's key gives, none for one of no passkey's form. */
function reference(jwk: unknown): string | undefined {
	if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) return undefined;
	const k = jwk as Record<string, unknown>;
	const keys = Object.keys(k).sort().join(",");
	const ok =
		k.kty === "EC"
			? keys === "crv,kty,x,y" &&
				k.crv === "P-256" &&
				spells(k.x, (n) => n === 32) &&
				spells(k.y, (n) => n === 32)
			: k.kty === "OKP"
				? keys === "crv,kty,x" && k.crv === "Ed25519" && spells(k.x, (n) => n === 32)
				: k.kty === "RSA"
					? keys === "e,kty,n" && k.e === "AQAB" && modulus(k.n)
					: false;
	// Members sorted, no space: no member is integer-like, so JSON writes them in this order.
	return ok
		? JSON.stringify(
				Object.fromEntries(
					Object.keys(k)
						.sort()
						.map((m) => [m, k[m]]),
				),
			)
		: undefined;
}

const bytes = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
/** A modulus's bytes at and past each bound: 255, 256, 257, 512, 513 long; its high byte 0, 0x7f, 0x80 or any; odd or not. */
const modulusBytes = fc
	.tuple(
		fc.constantFrom(255, 256, 257, 384, 512, 513),
		fc.constantFrom(0x00, 0x7f, 0x80, -1),
		fc.boolean(),
	)
	.chain(([n, high, odd]) =>
		bytes(n).map((b) => {
			const out = new Uint8Array(b);
			if (high >= 0) out[0] = high;
			out[n - 1] = odd ? (out[n - 1] ?? 0) | 1 : (out[n - 1] ?? 0) & 0xfe;
			return out;
		}),
	);
/** A text of another spelling of bytes, or none of them: padded, its last character's spare bits set, one too few or many. */
const misspelt = (good: string) =>
	fc.constantFrom(
		`${good}=`,
		// The last character's lowest bit flipped: a spare bit where the bytes end short of it, the same length.
		`${good.slice(0, -1)}${alphabet[alphabet.indexOf(good.slice(-1)) ^ 1]}`,
		good.slice(0, -1),
		// One character more, an odd one, so a length of no bytes is what refuses it.
		`${good}B`,
		good.replace(/./, "+"),
	);
const ec = fc.record({
	crv: fc.constant("P-256"),
	kty: fc.constant("EC"),
	x: bytes(32).map(b64),
	y: bytes(32).map(b64),
});
const okp = fc.record({
	crv: fc.constant("Ed25519"),
	kty: fc.constant("OKP"),
	x: bytes(32).map(b64),
});
const rsa = fc.record({
	e: fc.constant("AQAB"),
	kty: fc.constant("RSA"),
	n: modulusBytes.map(b64),
});
/** A key changed once as a sender can: a member added, dropped, misspelt, of another type or value. */
const changed = (key: Record<string, unknown>) =>
	fc.oneof(
		fc.constant(key),
		fc.constantFrom("kid", "alg", "use", "d", "__proto__").map((m) => ({ ...key, [m]: "x" })),
		fc
			.constantFrom(...Object.keys(key))
			.map((m) => Object.fromEntries(Object.entries(key).filter(([k]) => k !== m))),
		fc
			.constantFrom(
				...Object.keys(key).filter((m) => typeof key[m] === "string" && m !== "kty" && m !== "crv"),
			)
			.chain((m) => misspelt(key[m] as string).map((v) => ({ ...key, [m]: v }))),
		fc
			.constantFrom(...Object.keys(key))
			.chain((m) => fc.constantFrom(1, null, [], {}, "", "AQAB").map((v) => ({ ...key, [m]: v }))),
		fc
			.constantFrom({ crv: "P-384" }, { crv: "Ed448" }, { kty: "oct" }, { e: "AQAC" })
			.map((v) => ({ ...key, ...v })),
	);

describe("a passkey's public key as the wire reads it", () => {
	it("gives the thumbprint's input exactly where a reference written apart does, the RFC 7638 text, for each key type and any change", () => {
		const seen = { ec: 0, okp: 0, rsa: 0, refused: 0 };
		fc.assert(
			fc.property(fc.oneof(ec, okp, rsa).chain(changed), (jwk) => {
				const got = passkeyThumbprintInput(jwk);
				expect(got).toBe(reference(jwk));
				if (got === undefined) seen.refused++;
				else seen[(jwk as { kty: string }).kty.toLowerCase() as "ec" | "okp" | "rsa"]++;
			}),
			{ seed, numRuns },
		);
		for (const [what, n] of Object.entries(seen)) expect(n, what).toBeGreaterThan(0);
	});

	it("never throws, giving none, for a value of no key's form", () => {
		fc.assert(
			fc.property(fc.anything(), (value) => {
				expect(passkeyThumbprintInput(value)).toBe(reference(value));
			}),
			{ seed, numRuns },
		);
	});

	it("takes a modulus at each bound alone: 2048 bits with the high bit set, to 4096, odd, no leading zero", () => {
		const at = (n: number, high: number, odd = true) => {
			const b = new Uint8Array(n).fill(0x55);
			b[0] = high;
			b[n - 1] = odd ? 0x01 : 0x02;
			return passkeyThumbprintInput({ e: "AQAB", kty: "RSA", n: b64(b) }) !== undefined;
		};
		expect([
			at(255, 0xff),
			at(256, 0x7f),
			at(256, 0x80),
			at(257, 0x01),
			at(512, 0xff),
			at(513, 0x01),
		]).toEqual([false, false, true, true, true, false]);
		expect([at(256, 0x00), at(257, 0x00), at(256, 0x80, false)]).toEqual([false, false, false]);
	});
});
