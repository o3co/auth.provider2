import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { assemble, type BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { promiseNames, stances } from "@mod/promises";
import { CompactSign, decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { accessTokenSigning, keys, type Signed } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const january = Date.parse("2026-01-01T00:00:00Z");
let now = january;
afterEach(() => {
	now = january;
});
const runtime = quietRuntime({ clock: { now: () => now } });

const ed25519 = () => generateKeyPairSync("ed25519");
const bytes = (claims: unknown) => new TextEncoder().encode(JSON.stringify(claims));
const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};

const current = ed25519();
const old = ed25519();
const coming = ed25519();
const held: Readonly<Record<string, KeyObject>> = {
	now: current.privateKey,
	next: coming.publicKey,
	old: old.publicKey,
};
const rotated = keysConfig({
	authority: {
		signing: { kid: "now", alg: "EdDSA" },
		next: { kid: "next", alg: "EdDSA" },
		previous: [{ kid: "old", alg: "EdDSA", "expires-at": "2026-06-01T00:00:00Z" }],
	},
});

async function open(at = runtime) {
	const app = await assemble({
		modules: [keysModule, testHolder(held)],
		config: { ...kernelConfig(), ...rotated },
		runtime: at,
	});
	return { access: app.get(accessTokenSigning), k: app.get(keys) };
}

const signedBy = (key: KeyObject, kid: string, typ: string) =>
	new CompactSign(bytes({ sub: "a" })).setProtectedHeader({ alg: "EdDSA", typ, kid }).sign(key);

describe("accessTokenSigning", () => {
	it("signs the claims as they are as an at+jwt with the authority's current key, and verifies it [oidc-core-10.1-d]", async () => {
		const { access } = await open();
		const token = jwsOf(await access.sign(access.prepare(), bytes({ sub: "a", scope: "read" })));
		expect(decodeProtectedHeader(token)).toEqual({ alg: "EdDSA", typ: "at+jwt", kid: "now" });
		const verified = await access.verify(token);
		expect(verified).toEqual({ kind: "valid", claims: { sub: "a", scope: "read" } });
		expect(verified.kind === "valid" && Object.isFrozen(verified.claims)).toBe(true);
	});

	it("refuses to sign claims holding a null, at any depth, on either ring and as an access token alike, naming the claims and not their values [oidc-core-13.3-a]", async () => {
		const recorded = recordingLog();
		const { access, k } = await open(
			quietRuntime({ clock: { now: () => now }, log: recorded.log }),
		);
		const claims = bytes({
			sub: "a",
			secret: "kept-value",
			nonce: null,
			address: { region: null },
		});
		const refusal = /^keys: claims are null: nonce address\.region$/;
		await expect(access.sign(access.prepare(), claims)).rejects.toThrow(refusal);
		await expect(k.sign(k.prepare("authority", "JWT"), claims)).rejects.toThrow(refusal);
		await expect(k.sign(k.prepare("core", "approval+jwt"), claims)).rejects.toThrow(refusal);
		await expect(
			k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a", list: [{ item: null }] })),
		).rejects.toThrow(/claims are null: list\[0\]\.item$/);
		await expect(access.sign(access.prepare(), claims)).rejects.not.toThrow(/kept-value/);
		// keys logs the claims it refused by their paths, as the caller's failure is logged by its kind alone.
		expect(recorded.lines().find((line) => line.event === "keys.null_claims")).toEqual({
			level: "error",
			event: "keys.null_claims",
			fields: { claims: "nonce address.region" },
		});
		expect(JSON.stringify(recorded.lines())).not.toContain("kept-value");
		// A number JSON cannot hold is written as null by the caller's encoding, and refused so.
		await expect(
			access.sign(access.prepare(), bytes({ sub: "a", exp: Number.NaN })),
		).rejects.toThrow(/claims are null: exp$/);
		expect(jwsOf(await access.sign(access.prepare(), bytes({ sub: "a", scope: "read" })))).toMatch(
			/^[\w-]+\.[\w-]+\.[\w-]+$/,
		);
	});

	it("refuses a token of any other typ, and a malformed one, as keys.verify does", async () => {
		const { access, k } = await open();
		expect(
			await access.verify(jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })))),
		).toEqual({ kind: "invalid", reason: "typ" });
		expect(await access.verify("not a jws")).toEqual({ kind: "invalid", reason: "malformed" });
	});

	it("verifies under the authority's ring as keys.verify does: the previous key until it expires, the next key, never another kid", async () => {
		const { access } = await open();
		const byOld = await signedBy(old.privateKey, "old", "at+jwt");
		expect((await access.verify(byOld)).kind).toBe("valid");
		expect((await access.verify(await signedBy(coming.privateKey, "next", "at+jwt"))).kind).toBe(
			"valid",
		);
		expect(await access.verify(await signedBy(ed25519().privateKey, "nobody", "at+jwt"))).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		now = Date.parse("2026-06-01T00:00:00Z");
		expect(await access.verify(byOld)).toEqual({ kind: "invalid", reason: "kid_expired" });
	});

	it("is the only way to an access token: keys' sign and verify refuse its typ on either ring, in any case or as a media type", async () => {
		const { access, k } = await open();
		const token = jwsOf(await access.sign(access.prepare(), bytes({ sub: "a" })));
		for (const typ of [
			"at+jwt",
			"AT+JWT",
			"At+Jwt",
			"application/at+jwt",
			"Application/AT+JWT",
			// A media type's parameters, and the space around them, name the same type.
			"application/at+jwt; charset=UTF-8",
			"AT+JWT;x=1",
			" at+jwt ",
			"Application/At+Jwt ; q=0.5",
		]) {
			for (const ring of ["authority", "core"] as const) {
				expect(() => k.prepare(ring, typ), typ).toThrow(TypeError);
				await expect(k.verify(ring, token, typ), typ).rejects.toThrow(TypeError);
			}
		}
		// Other types are signed and verified as before.
		for (const typ of ["JWT", "logout+jwt", "at+jwt2", "application/jwt"]) {
			const signed = jwsOf(await k.sign(k.prepare("authority", typ), bytes({ sub: "a" })));
			expect((await k.verify("authority", signed, typ)).kind, typ).toBe("valid");
		}
	});

	it("is taken only by a module that declares where it stands on the promises", async () => {
		const taking = (declares: boolean) =>
			defineModule({ name: "tokens", replicaSafe: true, takes: [accessTokenSigning] }, (m) =>
				declares
					? [
							m.contribute(stances).by(() => ({
								promise: promiseNames.clientToken,
								holds: true,
								by: "tokens",
							})),
						]
					: [],
			);
		const boot = (declares: boolean) =>
			assemble({
				modules: [keysModule, testHolder(held), taking(declares)],
				config: { ...kernelConfig(), ...rotated },
				runtime,
			});
		const unsaid = await boot(false).catch((error: unknown) => error);
		expect((unsaid as BootRefused).refusals).toEqual([
			{
				where: "tokens",
				reason:
					"keys.access-signing is taken only by a module that contributes to promises.stances",
			},
		]);
		await expect(boot(true)).resolves.toBeDefined();
	});
});
