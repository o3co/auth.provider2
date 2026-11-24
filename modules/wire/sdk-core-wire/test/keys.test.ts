import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { keyThumbprintInput, payloads, purposes, versions } from "../src/contract.ts";

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
			const input = keyThumbprintInput(v.jwk);
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
			expect(keyThumbprintInput(spki.export({ format: "jwk" }))).toBe(v.input);
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
		expect(keyThumbprintInput(jwk)).toBeUndefined();
	});

	it("has none for a value that is no JWK", () => {
		for (const value of [undefined, null, "key", 1, [], {}])
			expect(keyThumbprintInput(value)).toBeUndefined();
	});
});

describe("the statements' version and the key's thumbprint", () => {
	const key = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;
	const common = { iss: "i", sid: "s", iat: 1, exp: 2, e_enc: "e", e_sig: key, nonce: "n" };
	const named = { creation_hash: "c", credential_id: "cr", reservation_id: "r" };
	const possession = (p: object, v?: number) =>
		payloads.possession.safeParse({
			...common,
			...(v === undefined ? {} : { v }),
			purpose: purposes.possession,
			possession: { ...named, ...p },
		}).success;
	const jkt = vectors.accepted[0]?.jkt;

	it("speaks version 1, frozen", () => {
		expect(versions).toEqual([1]);
		expect(Object.isFrozen(versions)).toBe(true);
	});

	it("names the new key by its thumbprint or by its point's hash, one of the two", () => {
		expect(possession({ key_jkt: jkt })).toBe(true);
		expect(possession({ key_hash: "h" })).toBe(true);
		expect(possession({ key_jkt: jkt, key_hash: "h" })).toBe(false);
		expect(possession({})).toBe(false);
	});

	it("takes a thumbprint in its one spelling alone", () => {
		expect(possession({ key_jkt: `${jkt?.slice(0, 42)}B` })).toBe(false);
		expect(possession({ key_jkt: `${jkt}=` })).toBe(false);
	});

	it("takes a version it speaks, or none", () => {
		expect(possession({ key_jkt: jkt }, 1)).toBe(true);
		expect(possession({ key_jkt: jkt }, 2)).toBe(false);
		const completion = { iss: "i", t_hash: "t", assertion_hash: "a", code: "c", iat: 1, exp: 2 };
		expect(payloads.completion.safeParse({ ...completion, v: 1 }).success).toBe(true);
		expect(payloads.completion.safeParse({ ...completion, v: 0 }).success).toBe(false);
	});

	it("binds the algorithms a creation offered, each one a passkey may be of and named once", () => {
		const creation = (algorithms?: unknown) =>
			payloads.creation.safeParse({
				...common,
				purpose: purposes.creation,
				creation: {
					account: "a***",
					evidence: "ev",
					ct_hash: "ct",
					subject: "s",
					kg: 0,
					options: {
						user_id: "u",
						rp_id: "id.example",
						exclude_credentials: [],
						...(algorithms === undefined ? {} : { algorithms }),
					},
				},
			}).success;
		expect(creation()).toBe(true);
		expect(creation([-7, -8, -257])).toBe(true);
		expect(creation([])).toBe(false);
		expect(creation([-7, -7])).toBe(false);
		expect(creation([-35])).toBe(false);
	});
});
