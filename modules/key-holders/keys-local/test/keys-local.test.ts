import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assemble, BootRefused, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys, type Signed } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { hpke } from "@mod/sdk-core-wire";
import { decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import keysLocal from "../src/module.ts";
import { section as localSection } from "../src/section.ts";

const runtime = quietRuntime();
const privatePem = (key: KeyObject) => key.export({ format: "pem", type: "pkcs8" }).toString();
const publicPem = (key: KeyObject) => key.export({ format: "pem", type: "spki" }).toString();
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const bytes = (claims: unknown) => new TextEncoder().encode(JSON.stringify(claims));
const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};
/** A self-signed P-256 certificate, made with openssl for these tests. */
const certificate = `-----BEGIN CERTIFICATE-----
MIIBJzCBzgIJAOKAR396qLcxMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEHBlbS1m
b3JtLWZpeHR1cmUwIBcNMjYxMTA4MTUzOTI1WhgPMjEyNjEwMTUxNTM5MjVaMBsx
GTAXBgNVBAMMEHBlbS1mb3JtLWZpeHR1cmUwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATS/vB1y2OAZTjtIiq1h3wF3kwoWiVobLWC+5gft5EyatdMo3K85KQBg/7d
UgN11ZspuX7pxRH/tCxxqMyGXZtjMAoGCCqGSM49BAMCA0gAMEUCIQCteb0i+M7Y
849mU13UrKu+nKuKZ44vQOOLCQiKmdBmkQIgXerbgVMU4hCgxzMY+DTCvAl0GPA2
ERFQaUYoKVNYuAQ=
-----END CERTIFICATE-----
`;

const signing = p256();
const core = p256();
const sealing = p256();
/** keys-local's entries for the test configuration's kids. */
const held = (more: readonly unknown[] = []) => [
	{ kid: "test", pem: privatePem(signing.privateKey) },
	{ kid: "core-test", pem: privatePem(core.privateKey) },
	{ kid: "seal-test", pem: privatePem(sealing.privateKey) },
	...more,
];

let dir = "";
afterEach(async () => {
	if (dir) await rm(dir, { recursive: true, force: true });
	dir = "";
});

async function boot(
	entries: readonly unknown[],
	settings: Record<string, unknown> = {},
	more: readonly Module[] = [],
	promisesConfig: Record<string, unknown> = {},
) {
	return assemble({
		modules: [keysModule, keysLocal, ...more],
		config: {
			...kernelConfig(),
			...keysConfig(settings),
			"keys-local": { keys: entries },
			...(more.includes(promisesModule) ? { promises: promisesConfig } : {}),
		},
		runtime,
	});
}

async function refusalsOf(entries: readonly unknown[], settings: Record<string, unknown> = {}) {
	const refused = await boot(entries, settings).catch((error: unknown) => error);
	if (!BootRefused.is(refused)) throw new Error("expected a refusal");
	return (refused as BootRefused).refusals;
}

describe("keys-local", () => {
	it("signs with the private keys written in its section, as keys asks, on either ring", async () => {
		const k = (await boot(held())).get(keys);
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(decodeProtectedHeader(token)).toEqual({ alg: "ES256", typ: "JWT", kid: "test" });
		expect((await k.verify("authority", token, "JWT")).kind).toBe("valid");
		const statement = jwsOf(
			await k.sign(k.prepare("core", "approval+jwt"), bytes({ purpose: "authorization" })),
		);
		expect((await k.verify("core", statement, "approval+jwt")).kind).toBe("valid");
	});

	it("signs under EdDSA and RS256 too, by the key's kind", async () => {
		for (const [alg, pair] of [
			["EdDSA", generateKeyPairSync("ed25519")],
			["RS256", generateKeyPairSync("rsa", { modulusLength: 2048 })],
		] as const) {
			const k = (
				await boot(held([{ kid: "k", pem: privatePem(pair.privateKey) }]), {
					authority: { signing: { kid: "k", alg } },
				})
			).get(keys);
			const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
			expect((await k.verify("authority", token, "JWT")).kind, alg).toBe("valid");
		}
	});

	it("reads a key from a file the section names", async () => {
		dir = await mkdtemp(join(tmpdir(), "keys-local-"));
		const path = join(dir, "signing.pem");
		await writeFile(path, privatePem(signing.privateKey));
		const k = (await boot([{ kid: "test", file: path }, ...held().slice(1)])).get(keys);
		expect((await k.sign(k.prepare("authority", "JWT"), bytes({}))).kind).toBe("signed");
	});

	it("takes a key that only verifies as a public PEM, a certificate, or a private PEM for its public half alone", async () => {
		const previous = generateKeyPairSync("ed25519");
		const coming = p256();
		const settings = {
			authority: {
				signing: { kid: "test", alg: "ES256" },
				next: { kid: "next", alg: "ES256" },
				previous: [
					{ kid: "old", alg: "EdDSA", "expires-at": "2999-01-01T00:00:00Z" },
					{ kid: "cert", alg: "ES256", "expires-at": "2999-01-01T00:00:00Z" },
				],
			},
		};
		const k = (
			await boot(
				held([
					{ kid: "old", pem: privatePem(previous.privateKey) },
					{ kid: "cert", pem: certificate },
					{ kid: "next", pem: publicPem(coming.publicKey) },
				]),
				settings,
			)
		).get(keys);
		dir = await mkdtemp(join(tmpdir(), "keys-local-"));
		await k.publish([dir]);
		const published = JSON.parse(await readFile(join(dir, "jwks.json"), "utf8")) as {
			keys: Record<string, unknown>[];
		};
		expect(published.keys.map((key) => key.kid)).toEqual(["test", "old", "cert", "next"]);
		expect(published.keys.every((key) => !("d" in key))).toBe(true);
	});

	it("opens what a screen sealed to the sealing key it holds", async () => {
		const k = (await boot(held())).get(keys);
		const jwk = sealing.publicKey.export({ format: "jwk" });
		const point = new Uint8Array(
			Buffer.concat([
				Buffer.of(4),
				Buffer.from(jwk.x as string, "base64url"),
				Buffer.from(jwk.y as string, "base64url"),
			]),
		);
		const aad = new TextEncoder().encode("aad");
		// Sealed as a screen seals to the pinned key: the sealing is the same either way.
		const sealed = await k.seal(point, hpke.info.firstKeyRequest, aad, bytes({ identifier: "a" }));
		const opened = await k.open(sealed, hpke.info.firstKeyRequest, aad);
		expect(opened.kind === "opened" && new TextDecoder().decode(opened.plaintext)).toBe(
			'{"identifier":"a"}',
		);
	});

	it("refuses in its section a key not written as PEM, a path and a PEM both or neither, and a kid twice", () => {
		const paths = (entries: readonly unknown[]) =>
			localSection.safeParse({ keys: entries }).error?.issues.map((i) => i.path.join("."));
		expect(paths([{ kid: "k", pem: "REPLACE-PKCS8-PEM-PRIVATE-KEY" }])).toEqual(["keys.0.pem"]);
		expect(paths([{ kid: "k", pem: privatePem(signing.privateKey), file: "/k.pem" }])).toEqual([
			"keys.0",
		]);
		expect(paths([{ kid: "k" }])).toEqual(["keys.0"]);
		expect(
			paths([
				{ kid: "k", file: "/a.pem" },
				{ kid: "k", file: "/b.pem" },
			]),
		).toEqual(["keys.1.kid"]);
		expect(localSection.safeParse({ keys: held() }).success).toBe(true);
	});

	it("refuses a PEM it cannot read as a key, the example's placeholder among them, and a file it cannot read, by the key's path", async () => {
		const unreadable =
			"not readable as a PEM key: write a PEM key, private where it signs (the example's REPLACE- placeholder is none)";
		const placeholder =
			"-----BEGIN PRIVATE KEY-----\nREPLACE-PKCS8-PEM-PRIVATE-KEY\n-----END PRIVATE KEY-----";
		expect(await refusalsOf([{ kid: "test", pem: placeholder }, ...held().slice(1)])).toEqual([
			{ where: "keys-local.keys.0.pem", reason: unreadable },
		]);
		expect(
			await refusalsOf([
				...held(),
				{ kid: "x", pem: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----" },
			]),
		).toEqual([{ where: "keys-local.keys.3.pem", reason: unreadable }]);
		expect(
			await refusalsOf([...held().slice(1), { kid: "test", file: "/no/such/key.pem" }]),
		).toEqual([
			{ where: "keys-local.keys.2.file", reason: "not readable: write the path of a PEM file" },
		]);
	});

	it("holds a signing key written as its public half as one keys cannot sign with", async () => {
		expect(
			await refusalsOf([{ kid: "test", pem: publicPem(signing.publicKey) }, ...held().slice(1)]),
		).toEqual([
			{
				where: "keys.authority.signing.kid",
				reason:
					"its holder does not sign with it under keys.authority.signing.alg: hold its private key",
			},
		]);
	});

	it("declares that the promise resting on keys no one can take out does not hold, naming why", async () => {
		const app = await boot(held(), {}, [promisesModule]);
		const contained = app
			.get(promises)
			.judgment()
			.find((j) => j.promise === promiseNames.coreContained);
		expect(contained).toEqual({
			promise: promiseNames.coreContained,
			held: false,
			basis: "declared",
			breaking: [
				{
					by: "keys-local",
					reason:
						"its keys are in the Core's memory: a compromised Core takes them out and signs on after it is stopped, and no signing is counted outside it",
				},
			],
		});
		expect(app.get(keys).powers()).toEqual({ withdrawable: false, countedOutside: false });
		const refused = await boot(held(), {}, [promisesModule], {
			required: [promiseNames.coreContained],
		}).catch((error: unknown) => error);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["promises.required.0"]);
	});
});
