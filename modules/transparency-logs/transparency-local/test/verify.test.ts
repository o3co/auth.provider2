import { constants, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { continuations } from "@mod/continuation-wire";
import { describe, expect, it } from "vitest";
import { digestOf, verifiedByOne, verifiedEsig } from "../src/verify.ts";

const b64 = (text: string) => Buffer.from(text).toString("base64url");
/** A compact JWS of the texts given, signed by `key` under `alg`. */
function jws(alg: string, key: KeyObject, header: string, payload: string) {
	const input = `${b64(header)}.${b64(payload)}`;
	const hash = { 256: "sha256", 384: "sha384", 512: "sha512" }[alg.slice(2)] ?? "sha256";
	const options = alg.startsWith("PS")
		? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(alg.slice(2)) / 8 }
		: alg.startsWith("RS")
			? { key, padding: constants.RSA_PKCS1_PADDING }
			: { key, dsaEncoding: "ieee-p1363" as const };
	return `${input}.${sign(hash, Buffer.from(input), options).toString("base64url")}`;
}

describe("a JWS verified by the one key given, as the Core's own readers take it", () => {
	const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const written = { ...rsa.publicKey.export({ format: "jwk" }), alg: "RS256", kid: "r1" };

	it.each(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])(
		"verifies %s under an RSA key, whatever alg the key itself names",
		(alg) => {
			const made = jws(alg, rsa.privateKey, JSON.stringify({ alg, typ: "dpop+jwt" }), "{}");
			expect(verifiedByOne(made, [written])).toMatchObject({ header: { alg } });
		},
	);

	it("reads a header or payload naming a member twice as JSON reads it, the last", () => {
		const made = jws("PS256", rsa.privateKey, '{"alg":"PS256"}', '{"iat":1,"iat":2}');
		expect(verifiedByOne(made, [written])).toMatchObject({ payload: { iat: 2 } });
	});

	it("verifies nothing by another key, or under an alg its kind does not fit", () => {
		const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const made = jws("PS256", other.privateKey, '{"alg":"PS256"}', "{}");
		expect(verifiedByOne(made, [written])).toBeUndefined();
		const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const es = jws("ES256", ec.privateKey, '{"alg":"ES256"}', "{}");
		expect(verifiedByOne(es, [written])).toBeUndefined();
	});

	it("reads a JWS whatever kid its header names, as dpop reads a proof by its jwk alone", () => {
		for (const header of ['{"alg":"PS256","kid":"r2"}', '{"alg":"PS256","kid":7}']) {
			const made = jws("PS256", rsa.privateKey, header, "{}");
			expect(verifiedByOne(made, [written]), header).toMatchObject({ payload: {} });
		}
	});
});

describe("a screen's continuation, as a browser's WebCrypto makes it", () => {
	const subtle = globalThis.crypto.subtle;
	const base64url = (bytes: ArrayBuffer) => Buffer.from(bytes).toString("base64url");
	const screenDigest = async (text: string) =>
		base64url(await subtle.digest("SHA-256", new TextEncoder().encode(text)));

	it("digests a text's UTF-8 bytes as the screen does, base64url", async () => {
		for (const text of ["abc", "créé ✓ 鍵", '{"id":"x"}'])
			expect(digestOf(text)).toBe(await screenDigest(text));
		expect(digestOf("abc")).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
	});

	it("digests a key change's possession and assertion as its writer names them (passkey-management's literal values)", () => {
		const possession =
			"eyJhbGciOiJFUzI1NiIsInR5cCI6ImFwcHJvdmFsK2p3dCJ9.eyJwdXJwb3NlIjoicG9zc2Vzc2lvbiJ9.c2lnbmF0dXJl";
		expect(digestOf(possession)).toBe("p_5wwYfl5sOtQrwnw4MimfuUx4yvVSMF8VDiOT2jKkI");
		expect(digestOf('{"id":"k1","response":{"signature":"c2ln"}}')).toBe(
			"sEEwzKWW5uZNa96UdjoUwblfaWD0INVCWBR3i4sCKf4",
		);
	});

	it("verifies E_sig's raw r||s over continuations.of's UTF-8, and nothing else", async () => {
		const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
			"verify",
		]);
		const { x = "", y = "" } = await subtle.exportKey("jwk", pair.publicKey);
		const input = continuations.of("register", digestOf("creation"), 1, digestOf("body"));
		const signed = base64url(
			await subtle.sign(
				{ name: "ECDSA", hash: "SHA-256" },
				pair.privateKey,
				new TextEncoder().encode(input),
			),
		);
		expect(verifiedEsig({ x, y }, input, signed)).toBe(true);
		const other = continuations.of("register", digestOf("creation"), 2, digestOf("body"));
		expect(verifiedEsig({ x, y }, other, signed)).toBe(false);
		expect(verifiedEsig({ x: y, y: x }, input, signed)).toBe(false);
		expect(verifiedEsig({ x, y }, input, `${signed.slice(0, -2)}AA`)).toBe(false);
		expect(verifiedEsig({ x: "", y }, input, signed)).toBe(false);
	});
});
