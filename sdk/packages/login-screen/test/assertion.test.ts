import { describe, expect, it, vi } from "vitest";
import { verifiedUnder } from "../src/assertion/assertion.ts";
import { derOf, passkeyAssertion } from "./fixtures.ts";

const challenge = "Y2hhbGxlbmdl";
type Key = Parameters<typeof verifiedUnder>[1];

/** The assertion's JSON with its signature replaced, base64url of the bytes given. */
const withSignature = (bytes: Uint8Array, signature: Uint8Array) => {
	const read = JSON.parse(new TextDecoder().decode(bytes));
	read.response.signature = Buffer.from(signature).toString("base64url");
	return new TextEncoder().encode(JSON.stringify(read));
};

// P-256, for Q*: the curve's prime, order, generator, and affine arithmetic over bigints.
const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G = {
	x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
	y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
type Point = { x: bigint; y: bigint } | undefined;
const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
const inverse = (a: bigint, m: bigint) => {
	let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
	while (r1 !== 0n) {
		const q = r0 / r1;
		[r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
	}
	return mod(s0, m);
};
const add = (a: Point, b: Point): Point => {
	if (!a) return b;
	if (!b) return a;
	if (a.x === b.x && mod(a.y + b.y, p) === 0n) return undefined;
	const l =
		a.x === b.x
			? mod(3n * a.x * a.x - 3n, p) * inverse(2n * a.y, p)
			: mod(b.y - a.y, p) * inverse(b.x - a.x, p);
	const x = mod(l * l - a.x - b.x, p);
	return { x, y: mod(l * (a.x - x) - a.y, p) };
};
const times = (k: bigint, at: Point): Point => {
	let [out, base, e] = [undefined as Point, at, mod(k, n)];
	while (e > 0n) {
		if (e & 1n) out = add(out, base);
		base = add(base, base);
		e >>= 1n;
	}
	return out;
};
const big = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
const b64 = (v: bigint) =>
	Buffer.from(v.toString(16).padStart(64, "0"), "hex").toString("base64url");

describe("the screen's own assertion, verified under the key a passkey-add's creation names (V30)", () => {
	it("verifies under its own key, P-256's and Ed25519's", async () => {
		for (const alg of ["ES256", "EdDSA"] as const) {
			const a = await passkeyAssertion(challenge, alg);
			expect(await verifiedUnder(a.bytes, a.jwk as Key, challenge), alg).toBe("verified");
		}
	});

	it("is unverified under another key, of its type or the other", async () => {
		const es = await passkeyAssertion(challenge, "ES256");
		const ed = await passkeyAssertion(challenge, "EdDSA");
		const other = await passkeyAssertion(challenge, "ES256");
		for (const [bytes, key] of [
			[es.bytes, other.jwk],
			[es.bytes, ed.jwk],
			[ed.bytes, es.jwk],
		] as const)
			expect(await verifiedUnder(bytes, key as Key, challenge)).toBe("unverified");
	});

	it("is unverified for another challenge or type, or bytes signed otherwise", async () => {
		const a = await passkeyAssertion(challenge);
		expect(await verifiedUnder(a.bytes, a.jwk as Key, "b3RoZXI")).toBe("unverified");
		const created = await passkeyAssertion(challenge, "ES256", { type: "webauthn.create" });
		expect(await verifiedUnder(created.bytes, created.jwk as Key, challenge)).toBe("unverified");
		const flipped = await passkeyAssertion(challenge, "ES256", {
			signed: (data) => Uint8Array.of(...data.subarray(0, -1), (data.at(-1) ?? 0) ^ 1),
		});
		expect(await verifiedUnder(flipped.bytes, flipped.jwk as Key, challenge)).toBe("unverified");
		for (const text of ["", "{}", "not json", JSON.stringify({ type: "public-key", response: {} })])
			expect(await verifiedUnder(new TextEncoder().encode(text), a.jwk as Key, challenge)).toBe(
				"unverified",
			);
	});

	it("reads ES256's DER strictly: one SEQUENCE of two shortest INTEGERs, each in [1, n−1], before WebCrypto is asked", async () => {
		// A signature whose r or s has its top bit set (about three in four do), for the negative case.
		let a = await passkeyAssertion(challenge);
		while (((a.raw[0] ?? 0) | (a.raw[32] ?? 0)) < 0x80) a = await passkeyAssertion(challenge);
		const r = big(a.raw.subarray(0, 32));
		const s = big(a.raw.subarray(32));
		const der = derOf(a.raw);
		/** A DER INTEGER of the value, in its shortest positive form. */
		const integer = (v: bigint) => {
			const hex = v.toString(16);
			const bytes = Buffer.from(hex.length % 2 ? `0${hex}` : hex, "hex");
			return Uint8Array.of(
				0x02,
				...((bytes[0] ?? 0) & 0x80 ? [bytes.length + 1, 0] : [bytes.length]),
				...bytes,
			);
		};
		const sequence = (rr: bigint, ss: bigint) => {
			const body = Uint8Array.of(...integer(rr), ...integer(ss));
			return Uint8Array.of(0x30, body.length, ...body);
		};
		/** The DER with its r's or s's leading zero dropped, where one has it; none where neither does. */
		const negativeOf = (signature: Uint8Array): Uint8Array[] => {
			const rLength = signature[3] ?? 0;
			const at = [3, 4 + rLength + 1].find((i) => signature[i] === 33 && signature[i + 1] === 0);
			if (at === undefined) throw new Error("no INTEGER with a leading zero");
			const body = Uint8Array.of(...signature.subarray(2, at), 32, ...signature.subarray(at + 2));
			return [Uint8Array.of(0x30, body.length, ...body)];
		};
		const verify = vi.spyOn(crypto.subtle, "verify");
		for (const bad of [
			Uint8Array.of(0x31, ...der.subarray(1)),
			Uint8Array.of(...der, 0),
			// An INTEGER not in its shortest form: r = 1 written in two bytes, its s a real one. Small
			// values, so no length bound refuses it first.
			Uint8Array.of(0x30, 4 + integer(s).length, 0x02, 0x02, 0x00, 0x01, ...integer(s)),
			sequence(0n, s),
			sequence(r, 0n),
			sequence(n, s),
			sequence(n + 1n, s),
			sequence(r, n),
			sequence(r, n + 1n),
			// Another tag than INTEGER's, and the SEQUENCE's length byte or end not its content's.
			Uint8Array.of(...der.subarray(0, 2), 0x03, ...der.subarray(3)),
			Uint8Array.of(0x30, (der[1] ?? 0) + 1, ...der.subarray(2)),
			// A byte past both INTEGERs inside the SEQUENCE, its length raised to hold it: small values again.
			Uint8Array.of(0x30, 7, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00),
			// A value whose top bit is set, its leading zero dropped: a negative INTEGER.
			...negativeOf(der),
			a.raw,
		])
			expect(await verifiedUnder(withSignature(a.bytes, bad), a.jwk as Key, challenge)).toBe(
				"unverified",
			);
		// Each refused on its form, never by WebCrypto's own check.
		expect(verify).not.toHaveBeenCalled();
		verify.mockRestore();
	});

	it("reads Ed25519's signature as its 64 bytes before WebCrypto is asked, S canonical, and takes no key of small order", async () => {
		const a = await passkeyAssertion(challenge, "EdDSA");
		const L = 2n ** 252n + 27742317777372353535851937790883648493n;
		const sOf = (sig: Uint8Array) =>
			BigInt(`0x${Buffer.from(sig.subarray(32)).reverse().toString("hex")}`);
		const withS = (v: bigint) =>
			Uint8Array.of(
				...a.raw.subarray(0, 32),
				...Buffer.from(v.toString(16).padStart(64, "0"), "hex").reverse(),
			);
		const verify = vi.spyOn(crypto.subtle, "verify");
		for (const bad of [a.raw.subarray(0, 63), Uint8Array.of(...a.raw, 0)])
			expect(await verifiedUnder(withSignature(a.bytes, bad), a.jwk as Key, challenge)).toBe(
				"unverified",
			);
		expect(verify).not.toHaveBeenCalled();
		verify.mockRestore();
		expect(
			await verifiedUnder(withSignature(a.bytes, withS(sOf(a.raw) + L)), a.jwk as Key, challenge),
		).toBe("unverified");
		const identity = Buffer.from(Uint8Array.of(1, ...new Uint8Array(31))).toString("base64url");
		expect(await verifiedUnder(a.bytes, { ...(a.jwk as Key), x: identity }, challenge)).toBe(
			"unverified",
		);
	});

	it("hashes the client data's bytes as the authenticator wrote them, not as JSON would write them again", async () => {
		const clientData = `{ "type" : "webauthn.get",\n "challenge": "${challenge}", "origin": "https:\\/\\/id.example" }`;
		const a = await passkeyAssertion(challenge, "ES256", { clientData });
		expect(JSON.stringify(JSON.parse(clientData))).not.toBe(clientData);
		expect(await verifiedUnder(a.bytes, a.jwk as Key, challenge)).toBe("verified");
	});

	it("reads the signature's form before the key: an ES256 assertion against an Ed25519 key is unverified, never unsupported", async () => {
		const es = await passkeyAssertion(challenge, "ES256");
		const ed = await passkeyAssertion(challenge, "EdDSA");
		const importKey = vi
			.spyOn(crypto.subtle, "importKey")
			.mockRejectedValue(new DOMException("no Ed25519", "NotSupportedError"));
		expect(await verifiedUnder(es.bytes, ed.jwk as Key, challenge)).toBe("unverified");
		expect(importKey).not.toHaveBeenCalled();
		importKey.mockRestore();
	});

	it("fails closed on a key that does not import, and tells a key type this browser cannot verify", async () => {
		const a = await passkeyAssertion(challenge);
		const off = { ...(a.jwk as Key), y: a.jwk.x as string };
		expect(await verifiedUnder(a.bytes, off, challenge)).toBe("unverified");
		const spy = vi
			.spyOn(crypto.subtle, "importKey")
			.mockRejectedValueOnce(new DOMException("no Ed25519", "NotSupportedError"));
		const ed = await passkeyAssertion(challenge, "EdDSA");
		expect(await verifiedUnder(ed.bytes, ed.jwk as Key, challenge)).toBe("unsupported");
		spy.mockRestore();
	});

	it("verifies too under Q*, the one other P-256 key the same signature does: why its guarantee is the key's possession, not this check", async () => {
		// Q* = −Q0 − 2(e/r)G, whose private key is −(d0 + 2e/r): known only to the holder of d0. A key goes
		// live on a flow only by its own possession proof, so Q* is never a parent the monitor holds.
		const a = await passkeyAssertion(challenge);
		const read = JSON.parse(new TextDecoder().decode(a.bytes)).response;
		const signed = Uint8Array.of(
			...Buffer.from(read.authenticatorData, "base64url"),
			...new Uint8Array(
				await crypto.subtle.digest("SHA-256", Buffer.from(read.clientDataJSON, "base64url")),
			),
		);
		const e = mod(big(new Uint8Array(await crypto.subtle.digest("SHA-256", signed))), n);
		const r = big(a.raw.subarray(0, 32));
		const q0 = {
			x: big(Buffer.from(a.jwk.x as string, "base64url")),
			y: big(Buffer.from(a.jwk.y as string, "base64url")),
		};
		const star = add({ x: q0.x, y: mod(-q0.y, p) }, times(mod(-2n * e * inverse(r, n), n), G));
		if (!star) throw new Error("no Q*");
		const key = { kty: "EC", crv: "P-256", x: b64(star.x), y: b64(star.y) } as Key;
		expect(key.x).not.toBe(a.jwk.x);
		expect(await verifiedUnder(a.bytes, key, challenge)).toBe("verified");
	});
});
