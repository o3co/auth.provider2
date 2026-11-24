import { constants, generateKeyPairSync, sign } from "node:crypto";
import type { Checks } from "@mod/authority-rules";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { accessTokenSigning, keys, type Prepared, type Signed } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const text = (value: string) => new TextEncoder().encode(value);
const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};
const segment = (jws: string, i: number) =>
	Buffer.from(jws.split(".")[i] as string, "base64url").toString();
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
// RSA keys are slow to make: made once, as the file loads, never within a test's time.
const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsa4608 = generateKeyPairSync("rsa", { modulusLength: 4608 });

async function booted(settings: Record<string, unknown> = {}, held = {}) {
	const app = await assemble({
		modules: [keysModule, testHolder(held)],
		config: { ...kernelConfig(), ...keysConfig(settings) },
		runtime: quietRuntime(),
	});
	return { k: app.get(keys), access: app.get(accessTokenSigning) };
}

describe("a signature prepared, then signed", () => {
	it("writes the prepared header byte for byte, so a digest taken of it and the claims before signing is the signed token's", async () => {
		const { k, access } = await booted();
		const claims = '{"sub":"a","txr":"receipt"}';
		for (const prepared of [
			k.prepare("authority", "JWT"),
			k.prepare("core", "approval+jwt"),
			access.prepare(),
		]) {
			expect(JSON.parse(prepared.headerText)).toEqual(prepared.header);
			const before = tokens.digestInput(prepared.headerText, claims);
			const sign =
				prepared.ring === "core" || prepared.header.typ !== "at+jwt" ? k.sign : access.sign;
			const jws = jwsOf(await sign(prepared, text(claims)));
			expect(segment(jws, 0)).toBe(prepared.headerText);
			expect(tokens.digestInput(segment(jws, 0), segment(jws, 1))).toEqual(before);
		}
		expect(k.prepare("authority", "JWT").header).toEqual({ alg: "ES256", typ: "JWT", kid: "test" });
		expect(k.prepare("core", "approval+jwt").header.kid).toBe("core-test");
		expect(access.prepare().header).toEqual({ alg: "ES256", typ: "at+jwt", kid: "test" });
	});

	it("says how long the signing key's signature is, byte for byte as signed: EdDSA, ES256, and PS256 and RS256 at its key's modulus", async () => {
		const keys = {
			ed: generateKeyPairSync("ed25519").privateKey,
			rsa: rsa4608.privateKey,
		};
		for (const [kid, alg] of [
			["test", "ES256"],
			["ed", "EdDSA"],
			["rsa", "PS256"],
			["rsa", "RS256"],
		] as const) {
			const { access } = await booted({ authority: { signing: { kid, alg } } }, keys);
			const prepared = access.prepare();
			const jws = jwsOf(await access.sign(prepared, text("{}")));
			const signature = Buffer.from(jws.split(".")[2] as string, "base64url");
			expect([alg, prepared.signatureLength]).toEqual([alg, signature.length]);
		}
	});

	it("signs only under a header it prepared: not another's, nor one made by hand", async () => {
		const { k, access } = await booted();
		const forged: Prepared = {
			ring: "authority",
			header: { alg: "ES256", typ: "JWT", kid: "test" },
			headerText: '{"alg":"ES256","typ":"JWT","kid":"test"}',
			signatureLength: 64,
		};
		await expect(k.sign(forged, text("{}"))).rejects.toThrow(TypeError);
		await expect(k.sign(access.prepare(), text("{}"))).rejects.toThrow(TypeError);
		await expect(access.sign(k.prepare("authority", "JWT"), text("{}"))).rejects.toThrow(TypeError);
		const prepared = k.prepare("authority", "JWT");
		expect(Object.isFrozen(prepared) && Object.isFrozen(prepared.header)).toBe(true);
	});

	it("refuses a payload naming a member twice, at any depth, which a reader would take one way and a signer another", async () => {
		const { k } = await booted();
		for (const payload of [
			'{"sub":"a","sub":"b"}',
			'{"a":{"x":1,"x":null}}',
			'{"a":1,"\\u0061":2}',
		]) {
			await expect(k.sign(k.prepare("authority", "JWT"), text(payload)), payload).rejects.toThrow(
				TypeError,
			);
		}
	});
});

describe("the Core's ring by generation", () => {
	const earlier = p256();
	const later = p256();
	const settings = {
		core: {
			generation: 2,
			keys: [
				{ generation: 1, kid: "core-1", alg: "ES256" },
				{ generation: 2, kid: "core-test", alg: "ES256" },
				{ generation: 3, kid: "core-3", alg: "ES256" },
			],
		},
	};
	const held = { "core-1": earlier.privateKey, "core-3": later.publicKey };

	it("gives a generation's public keys, each naming its generation, and none for a generation not in the ring", async () => {
		const { k } = await booted(settings, held);
		const ring = k.coreRing(1);
		expect(ring?.map((key) => [key.kid, key.alg, key.use, key.generation, "d" in key])).toEqual([
			["core-1", "ES256", "sig", 1, false],
		]);
		expect(k.coreRing(3)?.map((key) => key.kid)).toEqual(["core-3"]);
		expect(k.coreRing(4)).toBeUndefined();
	});

	it("gives every Core generation's public keys held, past, current and next, no private member among them", async () => {
		const { k } = await booted(settings, held);
		expect(k.coreRings().map((key) => [key.kid, key.generation, "d" in key])).toEqual([
			["core-1", 1, false],
			["core-test", 2, false],
			["core-3", 3, false],
		]);
	});

	it("verifies a JWS at once by the keys given, as authority-rules' checks take it, reading its header and payload", async () => {
		const { k } = await booted(settings, held);
		const checks: Pick<Checks, "verifyJws"> = { verifyJws: k.verifyJws };
		const statement = jwsOf(
			await k.sign(k.prepare("core", "approval+jwt"), text('{"purpose":"authorization"}')),
		);
		expect(checks.verifyJws(statement, k.coreRing(2) ?? [])).toEqual({
			header: { alg: "ES256", typ: "approval+jwt", kid: "core-test" },
			payload: { purpose: "authorization" },
		});
		// A generation's statement is no other generation's.
		expect(checks.verifyJws(statement, k.coreRing(1) ?? [])).toBeUndefined();
		expect(checks.verifyJws(statement, [])).toBeUndefined();
		// A key whose own alg is another, one with a private member, and a JWS not in its one form read as none.
		const [ours] = k.coreRing(2) ?? [];
		expect(checks.verifyJws(statement, [{ ...ours, alg: "RS256" }])).toBeUndefined();
		expect(checks.verifyJws(statement, [{ ...ours, d: "AAAA" }])).toBeUndefined();
		expect(checks.verifyJws(`${statement}=`, k.coreRing(2) ?? [])).toBeUndefined();
		const changed = `${statement.split(".")[0]}.${Buffer.from('{"purpose":"x"}').toString("base64url")}.${statement.split(".")[2]}`;
		expect(checks.verifyJws(changed, k.coreRing(2) ?? [])).toBeUndefined();
		// A key held for another use, or not for verifying, reads as none.
		expect(checks.verifyJws(statement, [{ ...ours, use: "enc" }])).toBeUndefined();
		expect(checks.verifyJws(statement, [{ ...ours, key_ops: ["encrypt"] }])).toBeUndefined();
		// A header nested past the reader's depth reads as none, and throws nothing.
		const deep = `${"[".repeat(6000)}${"]".repeat(6000)}`;
		const nested = `${Buffer.from(`{"alg":"ES256","kid":"core-test","x":${deep}}`).toString("base64url")}.${statement.split(".")[1]}.${statement.split(".")[2]}`;
		expect(checks.verifyJws(nested, k.coreRing(2) ?? [])).toBeUndefined();
	});

	it("verifies under EdDSA, PS256 and RS256 too, by the key's kind", async () => {
		for (const [alg, pair] of [
			["EdDSA", generateKeyPairSync("ed25519")],
			["PS256", rsa2048],
			["RS256", rsa2048],
		] as const) {
			const { k } = await booted(
				{ core: { generation: 1, keys: [{ generation: 1, kid: "c", alg }] } },
				{ c: pair.privateKey },
			);
			const jws = jwsOf(await k.sign(k.prepare("core", "approval+jwt"), text("{}")));
			expect(k.verifyJws(jws, k.coreRing(1) ?? []), alg).toEqual({
				header: { alg, typ: "approval+jwt", kid: "c" },
				payload: {},
			});
		}
	});

	it("refuses an RSA signature padded as the other algorithm, in the ring and among keys given", async () => {
		const pair = rsa2048;
		const pss = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
		for (const [alg, padding] of [
			["PS256", {}],
			["RS256", pss],
		] as const) {
			const { k } = await booted(
				{ core: { generation: 1, keys: [{ generation: 1, kid: "c", alg }] } },
				{ c: pair.privateKey },
			);
			const signed = jwsOf(await k.sign(k.prepare("core", "approval+jwt"), text("{}")));
			const input = signed.split(".").slice(0, 2).join(".");
			const other = sign("sha256", Buffer.from(input), { key: pair.privateKey, ...padding });
			const padded = `${input}.${other.toString("base64url")}`;
			expect(await k.verify("core", padded, "approval+jwt"), alg).toEqual({
				kind: "invalid",
				reason: "signature",
			});
			expect(k.verifyJws(padded, k.coreRing(1) ?? []), alg).toBeUndefined();
		}
	});
});
