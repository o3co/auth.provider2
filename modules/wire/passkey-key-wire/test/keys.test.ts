import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { type PasskeyPublicJwk, passkeyThumbprintInput } from "../src/contract.ts";

/** The shared vectors: each algorithm's key as COSE, SPKI and JWK with its thumbprint, and keys refused. */
interface Vectors {
	readonly accepted: readonly {
		readonly name: string;
		readonly alg: number;
		readonly cose: string;
		readonly spki: string;
		readonly jwk: Readonly<Record<string, string>>;
		readonly input: string;
		readonly jkt: string;
	}[];
	readonly jwkRefusals: readonly { readonly why: string; readonly jwk: unknown }[];
	readonly coseRefusals: readonly { readonly why: string; readonly cose: string }[];
}
const vectors: Vectors = JSON.parse(
	readFileSync(new URL("./keys.vectors.json", import.meta.url), "utf8"),
);

const hex = (base64url: string) => Buffer.from(base64url, "base64url").toString("hex");
/** A byte string's CBOR head and bytes, in its shortest form. */
const bstr = (base64url: string) => {
	const n = Buffer.from(base64url, "base64url").length;
	const head =
		n < 24
			? (0x40 + n).toString(16)
			: n < 256
				? `58${n.toString(16)}`
				: `59${n.toString(16).padStart(4, "0")}`;
	return `${head}${hex(base64url)}`;
};
/** The one COSE_Key form of each key type: CTAP2's canonical CBOR, its own labels alone, in order. */
const coseOf = (jwk: Readonly<Record<string, string>>) =>
	jwk.kty === "EC"
		? `a501020326200121${bstr(jwk.x ?? "")}22${bstr(jwk.y ?? "")}`
		: jwk.kty === "OKP"
			? `a401010327200621${bstr(jwk.x ?? "")}`
			: `a401030339010020${bstr(jwk.n ?? "")}21${bstr(jwk.e ?? "")}`;

describe("a passkey's key form", () => {
	it.each(vectors.accepted)(
		"gives $name's thumbprint input, the same from its COSE and its SPKI",
		(v) => {
			const input = passkeyThumbprintInput(v.jwk);
			expect(input).toBe(v.input);
			expect(
				createHash("sha256")
					.update(input ?? "")
					.digest("base64url"),
			).toBe(v.jkt);
			expect(coseOf(v.jwk)).toBe(v.cose);
			const spki = createPublicKey({
				key: Buffer.from(v.spki, "hex"),
				format: "der",
				type: "spki",
			});
			expect(passkeyThumbprintInput(spki.export({ format: "jwk" }))).toBe(v.input);
		},
	);

	it("names its members sorted, with no space, as RFC 7638 has them", () => {
		expect(vectors.accepted.map((v) => v.input.slice(0, 8))).toEqual([
			'{"crv":"',
			'{"crv":"',
			'{"e":"AQ',
			'{"e":"AQ',
		]);
		expect(vectors.accepted.every((v) => !v.input.includes(" "))).toBe(true);
	});

	it.each(vectors.jwkRefusals)("has no thumbprint input for $why", ({ jwk }) => {
		expect(passkeyThumbprintInput(jwk)).toBeUndefined();
	});

	it("has none for a value that is no JWK", () => {
		for (const value of [undefined, null, "key", 1, [], {}])
			expect(passkeyThumbprintInput(value)).toBeUndefined();
	});
});

describe("the vectors' reach", () => {
	// Every key type the JWK takes, by its type: one added to PasskeyPublicJwk fails to compile here.
	const keyTypes = { EC: true, OKP: true, RSA: true } satisfies Record<
		PasskeyPublicJwk["kty"],
		true
	>;

	it("hold at least one accepted key of every key type the JWK takes", () => {
		const held = new Set(vectors.accepted.map((v) => v.jwk.kty));
		for (const kty of Object.keys(keyTypes)) expect(held.has(kty), kty).toBe(true);
	});
});
