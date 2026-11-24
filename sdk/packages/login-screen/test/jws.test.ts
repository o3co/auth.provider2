import { describe, expect, it } from "vitest";
import { verifyCompact } from "../src/jws.ts";
import { signCompact, signingKey, type TestAlg } from "./fixtures.ts";

const payload = { a: 1, b: "two" };

describe("verifyCompact", () => {
	it("verifies a compact JWS under each algorithm the Core's ring may sign with", async () => {
		for (const alg of ["ES256", "EdDSA", "RS256", "PS256"] as const satisfies readonly TestAlg[]) {
			const key = await signingKey(alg);
			const jws = await signCompact(key, payload, { typ: "x+jwt" });
			expect(await verifyCompact(jws, [key.jwk]), alg).toEqual({
				header: { alg, kid: key.kid, typ: "x+jwt" },
				payload,
			});
		}
	});

	it("picks the key by kid among several", async () => {
		const a = await signingKey("ES256", "a");
		const b = await signingKey("ES256", "b");
		expect(await verifyCompact(await signCompact(b, payload), [a.jwk, b.jwk])).toMatchObject({
			payload,
		});
	});

	it("verifies nothing signed by another key, or altered", async () => {
		const key = await signingKey("ES256");
		const other = await signingKey("ES256");
		const jws = await signCompact(key, payload);
		expect(await verifyCompact(jws, [other.jwk])).toBeUndefined();
		const [h, p, s] = jws.split(".");
		const altered = `${h}.${Buffer.from(JSON.stringify({ a: 2, b: "two" })).toString("base64url")}.${s}`;
		expect(await verifyCompact(altered, [key.jwk])).toBeUndefined();
		expect(await verifyCompact(`${h}.${p}`, [key.jwk])).toBeUndefined();
		expect(await verifyCompact(`${jws}.x`, [key.jwk])).toBeUndefined();
	});

	it("verifies under the key's own algorithm alone: a header naming another, or none, is refused", async () => {
		const key = await signingKey("RS256");
		const asPs = { ...key.jwk, alg: "PS256" };
		expect(await verifyCompact(await signCompact(key, payload), [asPs])).toBeUndefined();
		expect(
			await verifyCompact(await signCompact(key, payload, { alg: "none" }), [key.jwk]),
		).toBeUndefined();
		expect(
			await verifyCompact(await signCompact(key, payload, { alg: "HS256" }), [key.jwk]),
		).toBeUndefined();
	});

	it("takes an EC or Ed25519 key with no alg by its curve, but no RSA key without one", async () => {
		const ec = await signingKey("ES256");
		const ed = await signingKey("EdDSA");
		const rsa = await signingKey("PS256");
		const strip = ({ alg: _alg, ...jwk }: JsonWebKey) => jwk;
		expect(await verifyCompact(await signCompact(ec, payload), [strip(ec.jwk)])).toBeDefined();
		expect(await verifyCompact(await signCompact(ed, payload), [strip(ed.jwk)])).toBeDefined();
		expect(await verifyCompact(await signCompact(rsa, payload), [strip(rsa.jwk)])).toBeUndefined();
	});

	it("refuses a header with crit or b64: an extension it does not implement", async () => {
		const key = await signingKey("ES256");
		for (const header of [{ crit: ["exp"], exp: 1 }, { b64: false, crit: ["b64"] }, { b64: true }])
			expect(
				await verifyCompact(await signCompact(key, payload, header), [key.jwk]),
				JSON.stringify(header),
			).toBeUndefined();
	});

	it("verifies with a key whose use is sig and whose key_ops hold verify, where it names them", async () => {
		const key = await signingKey("ES256");
		const jws = await signCompact(key, payload);
		expect(
			await verifyCompact(jws, [{ ...key.jwk, use: "sig", key_ops: ["verify"] }]),
		).toBeDefined();
		expect(await verifyCompact(jws, [{ ...key.jwk, use: "enc" }])).toBeUndefined();
		expect(await verifyCompact(jws, [{ ...key.jwk, key_ops: ["encrypt"] }])).toBeUndefined();
	});

	it("refuses an RSA key under 2048 bits", async () => {
		const pair = (await crypto.subtle.generateKey(
			{
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 1024,
				publicExponent: Uint8Array.of(1, 0, 1),
				hash: "SHA-256",
			},
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		const { key_ops: _o, ext: _e, ...jwk } = await crypto.subtle.exportKey("jwk", pair.publicKey);
		const small = {
			alg: "RS256" as const,
			kid: "small",
			privateKey: pair.privateKey,
			jwk: { ...jwk, alg: "RS256", kid: "small" },
		};
		expect(await verifyCompact(await signCompact(small, payload), [small.jwk])).toBeUndefined();
		const padded = Buffer.concat([
			Buffer.alloc(128),
			Buffer.from(small.jwk.n ?? "", "base64url"),
		]).toString("base64url");
		expect(
			await verifyCompact(await signCompact(small, payload), [{ ...small.jwk, n: padded }]),
		).toBeUndefined();
	});

	it("refuses a signature or a part in a base64url spelling that is not canonical", async () => {
		const key = await signingKey("EdDSA");
		const jws = await signCompact(key, payload);
		const [h, p, s = ""] = jws.split(".");
		const last = s.at(-1) ?? "A";
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const twin = alphabet[alphabet.indexOf(last) ^ 1] ?? "A";
		expect(await verifyCompact(`${h}.${p}.${s.slice(0, -1)}${twin}`, [key.jwk])).toBeUndefined();
	});

	it("verifies with no key whose public members are missing or not canonical", async () => {
		const key = await signingKey("ES256");
		const jws = await signCompact(key, payload);
		expect(await verifyCompact(jws, [{ ...key.jwk, y: `${key.jwk.y}=` }])).toBeUndefined();
		const { y: _y, ...noY } = key.jwk;
		expect(await verifyCompact(jws, [noY])).toBeUndefined();
	});

	it("refuses a key with a private member, and a header or payload that is no JSON object", async () => {
		const key = await signingKey("ES256");
		const exported = await crypto.subtle.exportKey("jwk", key.privateKey);
		expect(
			await verifyCompact(await signCompact(key, payload), [{ ...key.jwk, d: exported.d ?? "" }]),
		).toBeUndefined();
		expect(await verifyCompact(await signCompact(key, [1, 2]), [key.jwk])).toBeUndefined();
		expect(await verifyCompact("e30.e30.AA", [key.jwk])).toBeUndefined();
	});
});
