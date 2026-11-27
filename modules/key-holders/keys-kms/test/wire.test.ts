import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keys, type Signed } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { hpke } from "@mod/sdk-core-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import keysKmsModule from "../src/module.ts";
import { fakeKms, kmsServer } from "../src/testing.ts";

const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const sealing = p256();
const fake = fakeKms({
	[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("sealing")]: { key: sealing, spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
});
// The SDK's own chain, read from an environment the test sets whole: every AWS_ variable the run
// inherited is taken out first (an endpoint, a profile, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS), so no
// setting of the machine's can send a call anywhere but the server on loopback.
const own = (url: string, empty: string): Record<string, string> => ({
	AWS_ENDPOINT_URL_KMS: url,
	AWS_ACCESS_KEY_ID: "AKIDTESTONLY",
	AWS_SECRET_ACCESS_KEY: "test-only",
	AWS_CONFIG_FILE: empty,
	AWS_SHARED_CREDENTIALS_FILE: empty,
	AWS_EC2_METADATA_DISABLED: "true",
});
const inherited = () => Object.keys(process.env).filter((name) => name.startsWith("AWS_"));
const before = Object.fromEntries(inherited().map((name) => [name, process.env[name]]));
let server: Awaited<ReturnType<typeof kmsServer>>;
let dir = "";

beforeAll(async () => {
	server = await kmsServer(fake.kms);
	dir = await mkdtemp(join(tmpdir(), "keys-kms-wire-"));
	const empty = join(dir, "empty");
	await writeFile(empty, "");
	// A setting that would send the SDK to AWS were it left in place: taken out as any other.
	process.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS = "true";
	for (const name of inherited()) delete process.env[name];
	const set = own(server.url, empty);
	Object.assign(process.env, set);
	// Nothing boots unless the environment is exactly the test's own.
	if (inherited().sort().join() !== Object.keys(set).sort().join()) {
		throw new Error("an AWS_ variable of the run is still set");
	}
});

afterAll(async () => {
	for (const name of inherited()) delete process.env[name];
	for (const [name, value] of Object.entries(before)) {
		if (value !== undefined) process.env[name] = value;
	}
	await server.close();
	await rm(dir, { recursive: true, force: true });
});

const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};

/** The module composed as an app composes it, its sealing key the one given. */
const booted = (sealingKey: string) =>
	assemble({
		modules: [keysModule, keysKmsModule],
		config: {
			...kernelConfig(),
			...keysConfig(),
			"keys-kms": {
				region: "eu-west-1",
				keys: [
					{ kid: "test", "key-id": arn("authority") },
					{ kid: "core-test", "key-id": arn("core") },
					{ kid: "seal-test", "key-id": sealingKey },
				],
			},
		},
		runtime: quietRuntime(),
	});

describe("keys-kms through the SDK's client, at a KMS server on loopback", () => {
	it("boots as the module is composed, signs on either ring and opens what is sealed to it", async () => {
		const app = await booted(arn("sealing"));
		try {
			const k = app.get(keys);
			const claims = new TextEncoder().encode(JSON.stringify({ sub: "a" }));
			const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), claims));
			expect((await k.verify("authority", token, "JWT")).kind).toBe("valid");
			const point = new Uint8Array(
				Buffer.concat([
					Buffer.of(4),
					Buffer.from(sealing.export({ format: "jwk" }).x as string, "base64url"),
					Buffer.from(sealing.export({ format: "jwk" }).y as string, "base64url"),
				]),
			);
			const aad = new Uint8Array();
			const message = new TextEncoder().encode("first key");
			const sealed = await k.seal(point, hpke.info.firstKeyRequest, aad, message);
			expect(await k.open(sealed, hpke.info.firstKeyRequest, aad)).toMatchObject({
				kind: "opened",
			});
			expect(new Set(fake.calls.map((call) => call.command))).toEqual(
				new Set(["GetPublicKey", "Sign", "DeriveSharedSecret"]),
			);
		} finally {
			await app.stop();
		}
	});

	it("refuses boot at a key KMS answers it does not hold, by the error's name on the wire", async () => {
		const refused = await booted(arn("missing")).catch((error: unknown) => error);
		expect(BootRefused.is(refused)).toBe(true);
		const where = (refused as BootRefused).refusals.map((r) => r.where).join();
		expect(where).toMatch(/keys-kms\.keys/);
	});

	it("ends the connection where an answer does not serialize, never the host", async () => {
		fake.answer("Sign", { Signature: 1n });
		try {
			const app = await booted(arn("sealing"));
			try {
				const k = app.get(keys);
				const signed = k.sign(k.prepare("authority", "JWT"), new TextEncoder().encode("{}"));
				await expect(signed).rejects.toBeDefined();
			} finally {
				await app.stop();
			}
		} finally {
			fake.restore();
		}
	});

	it("refuses a body that is no JSON, and holds a request cut off while read, serving on", async () => {
		const url = new URL(server.url);
		const sent = (body: string, cut: boolean) =>
			new Promise<number | undefined>((done) => {
				const r = request(
					{
						host: url.hostname,
						port: url.port,
						method: "POST",
						headers: { "x-amz-target": "TrentService.GetPublicKey", "content-length": "100" },
					},
					(response) => {
						response.resume();
						done(response.statusCode);
					},
				);
				r.on("error", () => done(undefined));
				r.write(body);
				if (cut) setTimeout(() => r.destroy(), 20);
				else r.end("x".repeat(100 - body.length));
			});
		expect(await sent("{not json", false)).toBe(400);
		expect(await sent('{"KeyId":', true)).toBeUndefined();
		// Still serving: the next request is answered.
		expect(await sent("", false)).toBe(400);
	});
});
