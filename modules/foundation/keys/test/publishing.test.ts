import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import { keys } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const january = Date.parse("2026-01-01T00:00:00Z");
let now = january;
const runtime = quietRuntime({ clock: { now: () => now } });
let dir = "";
afterEach(async () => {
	now = january;
	if (dir) await rm(dir, { recursive: true, force: true });
});

const ed25519 = () => generateKeyPairSync("ed25519");
type Set = { keys: Record<string, unknown>[] };
const read = async (name: string) => JSON.parse(await readFile(join(dir, name), "utf8")) as Set;

async function boot(held: Readonly<Record<string, KeyObject>>, settings: Record<string, unknown>) {
	const app = await assemble({
		modules: [keysModule, testHolder(held)],
		config: { ...kernelConfig(), ...keysConfig(settings) },
		runtime,
	});
	dir = await mkdtemp(join(tmpdir(), "keys-publish-"));
	return app.get(keys);
}

describe("publishing the public keys to files", () => {
	const current = ed25519();
	const old = ed25519();
	const coming = ed25519();
	const held = { now: current.privateKey, old: old.privateKey, next: coming.publicKey };
	const authority = {
		signing: { kid: "now", alg: "EdDSA" },
		next: { kid: "next", alg: "EdDSA" },
		previous: [{ kid: "old", alg: "EdDSA", "expires-at": "2026-06-01T00:00:00Z" }],
	};

	it("writes the authority's set, the JWKS, of the public members of its unexpired keys, each for signatures [oidc-core-10.1.1-a] [oidc-core-10.2.1-a] [oidc-core-10.1-e]", async () => {
		const k = await boot(held, { authority });
		expect(await k.publish([dir])).toEqual({
			lines: [`wrote ${join(dir, "jwks.json")}`, `wrote ${join(dir, "core-keys.json")}`],
			code: 0,
		});
		const published = await read("jwks.json");
		expect(published.keys.map((key) => key.kid)).toEqual(["now", "old", "next"]);
		expect(published.keys.map((key) => [key.alg, key.use, key.kty, key.crv])).toEqual(
			Array(3).fill(["EdDSA", "sig", "OKP", "Ed25519"]),
		);
		// A key held privately is published by its public half alone.
		expect(published.keys.every((key) => !("d" in key))).toBe(true);
		now = Date.parse("2026-07-01T00:00:00Z");
		await k.publish([dir]);
		expect((await read("jwks.json")).keys.map((key) => key.kid)).toEqual(["now", "next"]);
		expect((await readdir(dir)).sort()).toEqual(["core-keys.json", "jwks.json"]);
	});

	it("writes the Core's ring, every generation's key for signatures naming its generation, and the sealing key for encryption, for the screen to pin", async () => {
		const later = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
		const k = await boot(
			{ ...held, "core-2": later },
			{
				authority,
				core: {
					generation: 1,
					keys: [
						{ generation: 2, kid: "core-2", alg: "ES256" },
						{ generation: 1, kid: "core-test", alg: "ES256" },
					],
				},
			},
		);
		await k.publish([dir]);
		const pinned = await read("core-keys.json");
		expect(pinned.keys.map((key) => [key.kid, key.alg, key.use, key.crv, key.generation])).toEqual([
			["core-test", "ES256", "sig", "P-256", 1],
			["core-2", "ES256", "sig", "P-256", 2],
			["seal-test", undefined, "enc", "P-256", undefined],
		]);
		expect(pinned.keys.every((key) => !("d" in key))).toBe(true);
	});

	it("answers a usage line and 64 where it is not given one directory", async () => {
		const k = await boot(held, { authority });
		for (const args of [[], [dir, dir]]) {
			expect(await k.publish(args)).toEqual({
				lines: ["usage: keys-publish <directory>"],
				code: 64,
			});
		}
		expect(await readdir(dir)).toEqual([]);
	});
});
