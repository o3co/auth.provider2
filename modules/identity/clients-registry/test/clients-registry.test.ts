import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import secretHashModule from "@mod/secret-hash/module";
import { afterEach, describe, expect, it } from "vitest";
import registryModule from "../src/module.ts";
import { publisherKey, signedBy } from "../src/testing.ts";

const publisher = publisherKey();
const version = (number: number, ids: readonly string[] = ["rp-1"]) => ({
	v: 1,
	version: number,
	issuedAt: 1_700_000_000,
	clients: ids.map((id) => ({ id, kind: "public", method: "none", sections: {} })),
});

/** A compact JWS with one bit of its signature's last byte flipped: always another signature. */
const tampered = (jws: string) => {
	const [head, payload, signature] = jws.split(".");
	const bytes = Buffer.from(signature ?? "", "base64url");
	bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
	return `${head}.${payload}.${bytes.toString("base64url")}`;
};

let dir = "";
afterEach(async () => {
	if (dir) await rm(dir, { recursive: true, force: true });
	dir = "";
});

/** The registry file written with `text`, and the section pointing at it. */
async function written(text: string, settings: Record<string, unknown> = {}) {
	dir = await mkdtemp(join(tmpdir(), "clients-registry-"));
	const file = join(dir, "registry.jws");
	await writeFile(file, text);
	return { file, "publisher-key": publisher.jwk, "min-version": 1, ...settings };
}

const modules = [
	clientsModule,
	secretHashModule,
	keysModule,
	testHolder(),
	promisesModule,
	registryModule,
];
const configOf = (section: Record<string, unknown>, registered: unknown[] = []) => ({
	...kernelConfig(),
	...keysConfig(),
	clients: { registered },
	"clients-registry": section,
});

async function boot(
	section: Record<string, unknown>,
	registered: unknown[] = [],
	log = recordingLog(),
) {
	return assemble({
		modules,
		config: configOf(section, registered),
		runtime: quietRuntime({ log: log.log }),
	});
}

async function refusalsOf(section: Record<string, unknown>) {
	const refused = await boot(section).catch((error: unknown) => error);
	if (!BootRefused.is(refused)) throw new Error("expected a refusal");
	return (refused as BootRefused).refusals;
}

describe("clients-registry", () => {
	it("answers the clients of the version the publisher signed, none of them registered", async () => {
		const app = await boot(await written(signedBy(publisher, version(3, ["rp-1", "rp-2"]))));
		const c = app.get(clients);
		expect((await c.find("rp-1"))?.registered).toBe(false);
		expect((await c.find("rp-2"))?.kind).toBe("public");
		expect(await c.find("rp-3")).toBeUndefined();
		// Each says the version it came from, and that its publisher signed it.
		expect((await c.find("rp-1"))?.version).toBe(3);
		expect((await c.find("rp-1"))?.signed).toBe(true);
		// Listed, for a boot check, as find answers them.
		expect((await c.listed()).map((client) => [client.id, client.signed])).toEqual([
			["rp-1", true],
			["rp-2", true],
		]);
		await app.stop();
	});

	it("takes a version signed under ES256 too, the key's kind naming the algorithm", async () => {
		const p256 = publisherKey("p256", "publisher-p256");
		const section = await written(signedBy(p256, version(1)), { "publisher-key": p256.jwk });
		const app = await boot(section);
		expect((await app.get(clients).find("rp-1"))?.id).toBe("rp-1");
		await app.stop();
	});

	it("leaves a client the operator registered under the same id as the operator wrote it", async () => {
		const section = await written(signedBy(publisher, version(1, ["shared"])));
		const app = await boot(section, [{ id: "shared", kind: "public", method: "none" }]);
		const shared = await app.get(clients).find("shared");
		expect([shared?.registered, shared?.signed]).toEqual([true, undefined]);
		await app.stop();
	});

	it("reads the file at boot alone: a version written after it changes nothing", async () => {
		const section = await written(signedBy(publisher, version(1, ["first"])));
		const app = await boot(section);
		await writeFile(section.file, signedBy(publisher, version(2, ["second"])));
		const c = app.get(clients);
		expect((await c.find("first"))?.id).toBe("first");
		expect(await c.find("second")).toBeUndefined();
		await app.stop();
	});

	it("logs the version it read and how many clients it holds, never an id", async () => {
		const log = recordingLog();
		const app = await boot(await written(signedBy(publisher, version(7, ["a", "b"]))), [], log);
		await app.start();
		expect(log.lines()).toContainEqual({
			level: "info",
			event: "clients-registry.read",
			fields: { version: 7, clients: 2 },
		});
		await app.stop();
	});

	it("refuses boot where the file cannot be read, naming no path", async () => {
		const section = await written("");
		const refusals = await refusalsOf({ ...section, file: join(dir, "missing.jws") });
		expect(refusals.map((r) => r.where)).toEqual(["clients-registry.file"]);
		expect(JSON.stringify(refusals)).not.toContain(dir);
	});

	it("refuses boot where the signature does not verify under the publisher's key", async () => {
		const other = publisherKey("ed25519", publisher.kid);
		for (const text of [
			signedBy(other, version(1)),
			tampered(signedBy(publisher, version(1))),
			"not a jws",
			signedBy({ ...publisher, kid: "another" }, version(1)),
		]) {
			const refusals = await refusalsOf(await written(text));
			expect(
				refusals.map((r) => r.where),
				text,
			).toEqual(["clients-registry.file"]);
		}
	});

	it("refuses boot where the signed header's typ is not the registry's", async () => {
		for (const typ of ["JWT", "Registry+JWT", undefined]) {
			const refusals = await refusalsOf(await written(signedBy(publisher, version(1), { typ })));
			expect(
				refusals.map((r) => r.reason),
				String(typ),
			).toEqual([expect.stringContaining("typ")]);
		}
	});

	it("refuses boot where the version does not fit registry-wire's schema", async () => {
		for (const payload of [
			{ ...version(1), extra: true },
			{ ...version(1), v: 2 },
			version(1, ["twice", "twice"]),
			[],
		]) {
			const refusals = await refusalsOf(await written(signedBy(publisher, payload)));
			expect(refusals.map((r) => r.where)).toEqual(["clients-registry.file"]);
			expect(refusals[0]?.reason).toContain("registry-wire");
		}
	});

	it("refuses boot where the version holds a client id no client can have, naming its place, never the id", async () => {
		for (const id of ["My App", "caf\u00e9", "a".repeat(65)]) {
			const refusals = await refusalsOf(await written(signedBy(publisher, version(1, ["ok", id]))));
			expect(refusals.map((r) => r.where)).toEqual(["clients-registry.file"]);
			expect(refusals[0]?.reason).toContain("clients.1.id");
			expect(refusals[0]?.reason).not.toContain(id);
		}
	});

	it("refuses boot where the version is below the least the operator takes", async () => {
		const refusals = await refusalsOf(
			await written(signedBy(publisher, version(4)), { "min-version": 5 }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["clients-registry.min-version"]);
		expect(refusals[0]?.reason).toContain("the file's version is below min-version");
		const app = await boot(await written(signedBy(publisher, version(5)), { "min-version": 5 }));
		await app.stop();
	});

	it("refuses boot where the publisher's key is no public JWK for EdDSA or ES256 with a kid", async () => {
		const { d: _private, ...publicPart } = publisher.privateKey.export({ format: "jwk" });
		const withPrivate = {
			...publisher.privateKey.export({ format: "jwk" }),
			kid: "k",
			alg: "EdDSA",
		};
		const { kid: _kid, ...noKid } = publisher.jwk;
		for (const key of [
			withPrivate,
			noKid,
			{ ...publisher.jwk, alg: "RS256" },
			{ ...publisher.jwk, alg: undefined },
			{ ...publisher.jwk, alg: "ES256" },
			{ ...publicPart, kid: "k", alg: "EdDSA", use: "enc" },
		]) {
			const section = await written(signedBy(publisher, version(1)), { "publisher-key": key });
			const refusals = await refusalsOf(section);
			expect(
				refusals.map((r) => r.where),
				JSON.stringify(key.alg),
			).toEqual(["clients-registry.publisher-key"]);
		}
	});

	it("stands breaking the Core's containment at its file: no one outside sees which version the Core answers by", async () => {
		const app = await boot(await written(signedBy(publisher, version(1))));
		const contained = app
			.get(promises)
			.judgment()
			.find((j) => j.promise === promiseNames.coreContained);
		expect(contained?.held).toBe(false);
		expect(contained?.breaking).toContainEqual({
			by: "clients-registry",
			setting: "clients-registry.file",
			reason: expect.stringContaining("boot"),
		});
		await app.stop();
	});

	it("refuses boot where it is required to hold the Core's containment", async () => {
		const refused = await assemble({
			modules,
			config: {
				...configOf(await written(signedBy(publisher, version(1)))),
				promises: { required: [promiseNames.coreContained] },
			},
			runtime: quietRuntime(),
		}).catch((error: unknown) => error);
		expect(BootRefused.is(refused)).toBe(true);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["promises.required.0"]);
	});

	it("takes nothing it does not use", async () => {
		const section = await written(signedBy(publisher, version(1)));
		const unused = await takesUnused({
			modules,
			config: configOf(section),
			runtime: quietRuntime(),
		});
		expect(unused["clients-registry"]).toBeUndefined();
	});
});
