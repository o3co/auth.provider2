import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { assemble, BootRefused, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys, type Signed } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { hpke } from "@mod/sdk-core-wire";
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { keysKms } from "../src/adapter.ts";
import { section as kmsSection } from "../src/section.ts";
import { type FakeKey, fakeKms, serviceError } from "../src/testing.ts";

const runtime = quietRuntime();
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const bytes = (claims: unknown) => new TextEncoder().encode(JSON.stringify(claims));
const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};
const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;

/** The fake's keys for the test configuration's kids, and those given. */
const fakeKeys = (more: Readonly<Record<string, FakeKey>> = {}): Record<string, FakeKey> => ({
	[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("sealing")]: { key: p256(), spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
	...more,
});
const entries = (more: readonly unknown[] = []) => [
	{ kid: "test", "key-id": arn("authority") },
	{ kid: "core-test", "key-id": arn("core") },
	{ kid: "seal-test", "key-id": arn("sealing") },
	...more,
];

async function boot(
	fake: ReturnType<typeof fakeKms>,
	listed: readonly unknown[] = entries(),
	settings: Record<string, unknown> = {},
) {
	return assemble({
		modules: [keysModule, keysKms(() => fake.kms)],
		config: {
			...kernelConfig(),
			...keysConfig(settings),
			"keys-kms": { region: "eu-west-1", keys: listed },
		},
		runtime,
	});
}

const refusalsOf = async (
	fake: ReturnType<typeof fakeKms>,
	listed: readonly unknown[] = entries(),
	settings: Record<string, unknown> = {},
) => {
	const refused = await boot(fake, listed, settings).catch((error: unknown) => error);
	if (!BootRefused.is(refused)) throw new Error("expected a refusal");
	return (refused as BootRefused).refusals;
};

describe("keys-kms", () => {
	it("signs on either ring through KMS's Sign, sending the signing input's SHA-256 alone", async () => {
		const fake = fakeKms(fakeKeys());
		const k = (await boot(fake)).get(keys);
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(decodeProtectedHeader(token)).toEqual({ alg: "ES256", typ: "JWT", kid: "test" });
		expect((await k.verify("authority", token, "JWT")).kind).toBe("valid");
		const statement = jwsOf(
			await k.sign(k.prepare("core", "approval+jwt"), bytes({ purpose: "authorization" })),
		);
		expect((await k.verify("core", statement, "approval+jwt")).kind).toBe("valid");
		const input = token.split(".").slice(0, 2).join(".");
		expect(fake.calls.find((call) => call.command === "Sign")?.input).toEqual({
			KeyId: arn("authority"),
			Message: new Uint8Array(createHash("sha256").update(input).digest()),
			MessageType: "DIGEST",
			SigningAlgorithm: "ECDSA_SHA_256",
		});
	});

	it("signs under PS256 and RS256 with an RSA key, each by its KMS algorithm", async () => {
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
		for (const [alg, algorithm] of [
			["PS256", "RSASSA_PSS_SHA_256"],
			["RS256", "RSASSA_PKCS1_V1_5_SHA_256"],
		] as const) {
			const fake = fakeKms(
				fakeKeys({ [arn("rsa")]: { key: rsa, spec: "RSA_2048", usage: "SIGN_VERIFY" } }),
			);
			const k = (
				await boot(fake, entries([{ kid: "r", "key-id": arn("rsa") }]), {
					authority: { signing: { kid: "r", alg } },
				})
			).get(keys);
			const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
			expect((await k.verify("authority", token, "JWT")).kind, alg).toBe("valid");
			expect(
				fake.calls
					.filter((c) => c.command === "Sign")
					.map((c) => (c.input as { SigningAlgorithm: string }).SigningAlgorithm),
			).toEqual([algorithm]);
		}
	});

	it("opens what a screen sealed to the sealing key through KMS's DeriveSharedSecret", async () => {
		const keysHeld = fakeKeys();
		const fake = fakeKms(keysHeld);
		const k = (await boot(fake)).get(keys);
		const jwk = (keysHeld[arn("sealing")] as FakeKey).key.export({ format: "jwk" });
		const point = new Uint8Array(
			Buffer.concat([
				Buffer.of(4),
				Buffer.from(jwk.x as string, "base64url"),
				Buffer.from(jwk.y as string, "base64url"),
			]),
		);
		const aad = new TextEncoder().encode("aad");
		const sealed = await k.seal(point, hpke.info.firstKeyRequest, aad, bytes({ identifier: "a" }));
		const opened = await k.open(sealed, hpke.info.firstKeyRequest, aad);
		expect(opened.kind === "opened" && new TextDecoder().decode(opened.plaintext)).toBe(
			'{"identifier":"a"}',
		);
		expect(
			fake.calls.filter((c) => c.command === "DeriveSharedSecret").map((c) => c.input),
		).toEqual([expect.objectContaining({ KeyId: arn("sealing"), KeyAgreementAlgorithm: "ECDH" })]);
	});

	it("answers withdrawn where KMS denies the Core or the key is disabled, and an outage as unavailable", async () => {
		const keysHeld = fakeKeys();
		const fake = fakeKms(keysHeld);
		const k = (await boot(fake)).get(keys);
		const sealed = await k.seal(
			new Uint8Array(createPublicKeyPoint((keysHeld[arn("sealing")] as FakeKey).key)),
			hpke.info.firstKeyRequest,
			new Uint8Array(),
			bytes({}),
		);
		for (const name of ["AccessDeniedException", "DisabledException", "KMSInvalidStateException"]) {
			fake.fail("*", serviceError(name));
			expect(await k.sign(k.prepare("authority", "JWT"), bytes({})), name).toEqual({
				kind: "withdrawn",
			});
			expect(await k.open(sealed, hpke.info.firstKeyRequest, new Uint8Array()), name).toEqual({
				kind: "withdrawn",
			});
		}
		for (const error of [
			serviceError("KMSInternalException", "server"),
			serviceError("ThrottlingException"),
			Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }),
		]) {
			fake.fail("*", error);
			const thrown = await k
				.sign(k.prepare("authority", "JWT"), bytes({}))
				.catch((e: unknown) => e);
			expect(isUnavailable(thrown), error.name).toBe(true);
		}
		fake.fail("*", serviceError("ValidationException"));
		const thrown = await k.sign(k.prepare("authority", "JWT"), bytes({})).catch((e: unknown) => e);
		expect([isUnavailable(thrown), (thrown as Error).name]).toEqual([false, "ValidationException"]);
	});

	it("signs after boot with the key the alias named at boot, whatever the alias names later", async () => {
		const keysHeld = fakeKeys({
			[arn("other")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
		});
		const fake = fakeKms(keysHeld, { "alias/authority": arn("authority") });
		const listed = [{ kid: "test", "key-id": "alias/authority" }, ...entries().slice(1)];
		const k = (await boot(fake, listed)).get(keys);
		fake.repoint("alias/authority", arn("other"));
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect((await k.verify("authority", token, "JWT")).kind).toBe("valid");
		expect(
			fake.calls
				.filter((call) => call.command === "Sign")
				.map((call) => (call.input as { KeyId: string }).KeyId),
		).toEqual([arn("authority")]);
	});

	it("fails, never answering an empty success, where KMS answers no signature, one that is no DER, or no secret", async () => {
		const keysHeld = fakeKeys();
		const fake = fakeKms(keysHeld);
		const k = (await boot(fake)).get(keys);
		const signing = () => k.sign(k.prepare("authority", "JWT"), bytes({}));
		for (const signature of [
			undefined,
			new Uint8Array(),
			new Uint8Array([0x30, 2, 2, 0]),
			new Uint8Array(64),
		]) {
			fake.answer("Sign", { Signature: signature });
			const thrown = await signing().catch((e: unknown) => e);
			expect([thrown instanceof Error, isUnavailable(thrown)], String(signature?.length)).toEqual([
				true,
				false,
			]);
		}
		fake.restore();
		const point = createPublicKeyPoint((keysHeld[arn("sealing")] as FakeKey).key);
		const sealed = await k.seal(
			new Uint8Array(point),
			hpke.info.firstKeyRequest,
			new Uint8Array(),
			bytes({}),
		);
		fake.answer("DeriveSharedSecret", { SharedSecret: undefined });
		await expect(k.open(sealed, hpke.info.firstKeyRequest, new Uint8Array())).rejects.toThrow(
			/no P-256 shared secret/,
		);
	});

	it("refuses boot, by the key's path, for a key KMS does not have, one the Core may not read, and no answer", async () => {
		expect(
			await refusalsOf(fakeKms(fakeKeys()), entries([{ kid: "gone", "key-id": arn("gone") }])),
		).toEqual([{ where: "keys-kms.keys.3.key-id", reason: "no such key in KMS" }]);
		const denied = fakeKms(fakeKeys());
		denied.fail("GetPublicKey", serviceError("AccessDeniedException"));
		expect((await refusalsOf(denied)).map((r) => [r.where, r.reason])).toEqual([
			["keys-kms.keys.0.key-id", "the Core may not read the key's public half (kms:GetPublicKey)"],
			["keys-kms.keys.1.key-id", "the Core may not read the key's public half (kms:GetPublicKey)"],
			["keys-kms.keys.2.key-id", "the Core may not read the key's public half (kms:GetPublicKey)"],
		]);
		const down = fakeKms(fakeKeys());
		down.fail("GetPublicKey", serviceError("KMSInternalException", "server"));
		expect((await refusalsOf(down))[0]).toEqual({
			where: "keys-kms.keys.0.key-id",
			reason: "KMS gave no answer for the key's public half",
		});
	});

	it("holds an Ed25519 key or an agreement key as one keys cannot sign with, and a signing key as none it agrees with", async () => {
		const ed = generateKeyPairSync("ed25519").privateKey;
		const fake = fakeKms(
			fakeKeys({ [arn("ed")]: { key: ed, spec: "ECC_NIST_EDWARDS25519", usage: "SIGN_VERIFY" } }),
		);
		expect(
			await refusalsOf(fake, entries([{ kid: "e", "key-id": arn("ed") }]), {
				authority: { signing: { kid: "e", alg: "EdDSA" } },
			}),
		).toEqual([
			{
				where: "keys.authority.signing.kid",
				reason:
					"its holder does not sign with it under keys.authority.signing.alg: hold its private key",
			},
		]);
		const swapped = [
			{ kid: "test", "key-id": arn("sealing") },
			{ kid: "core-test", "key-id": arn("core") },
			{ kid: "seal-test", "key-id": arn("authority") },
		];
		expect((await refusalsOf(fakeKms(fakeKeys()), swapped)).map((r) => r.where)).toEqual([
			"keys.authority.signing.kid",
			"keys.sealing.kid",
		]);
	});

	it("says its signing can be withdrawn outside the Core and that its calls are not counted outside it, and ends its client at stop", async () => {
		const fake = fakeKms(fakeKeys());
		const app = await boot(fake);
		expect(app.get(keys).powers()).toEqual({ withdrawable: true, countedOutside: false });
		await app.start();
		await app.stop(1000);
		expect(fake.destroyed()).toBe(true);
	});

	it("refuses in its section no region, a key without its id, and a kid twice", () => {
		const paths = (value: unknown) =>
			kmsSection.safeParse(value).error?.issues.map((i) => i.path.join("."));
		expect(paths({ keys: entries() })).toEqual(["region"]);
		expect(paths({ region: "eu-west-1", keys: [{ kid: "k" }] })).toEqual(["keys.0.key-id"]);
		expect(
			paths({
				region: "eu-west-1",
				keys: [
					{ kid: "k", "key-id": "a" },
					{ kid: "k", "key-id": "b" },
				],
			}),
		).toEqual(["keys.1.kid"]);
		expect(kmsSection.safeParse({ region: "eu-west-1", keys: entries() }).success).toBe(true);
	});
});

/** A P-256 key's point, uncompressed. */
function createPublicKeyPoint(key: KeyObject) {
	const jwk = key.export({ format: "jwk" });
	return Buffer.concat([
		Buffer.of(4),
		Buffer.from(jwk.x as string, "base64url"),
		Buffer.from(jwk.y as string, "base64url"),
	]);
}
