import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import registryModule from "@mod/clients-registry/module";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import secretHashModule from "@mod/secret-hash/module";
import { afterEach, expect, it } from "vitest";
import { signRegistry } from "../src/sign.ts";

let dir = "";
afterEach(async () => {
	if (dir) await rm(dir, { recursive: true, force: true });
	dir = "";
});

it("signs a version that clients-registry reads at boot, for each algorithm the tool signs under", async () => {
	for (const pair of [
		generateKeyPairSync("ed25519"),
		generateKeyPairSync("ec", { namedCurve: "P-256" }),
	]) {
		dir = await mkdtemp(join(tmpdir(), "registry-round-trip-"));
		const paths = {
			key: join(dir, "key.jwk"),
			input: join(dir, "v.json"),
			out: join(dir, "v.jws"),
		};
		const kid = "publisher-1";
		await writeFile(
			paths.key,
			JSON.stringify({ ...pair.privateKey.export({ format: "jwk" }), kid }),
		);
		await writeFile(
			paths.input,
			JSON.stringify({
				v: 1,
				version: 2,
				issuedAt: 1_700_000_000,
				clients: [{ id: "rp-1", kind: "public", method: "none", sections: {} }],
			}),
		);
		const signed = await signRegistry([paths.key, paths.input, paths.out]);
		expect(signed.code, signed.lines.join("\n")).toBe(0);
		const alg = pair.publicKey.asymmetricKeyType === "ed25519" ? "EdDSA" : "ES256";
		const app = await assemble({
			modules: [clientsModule, secretHashModule, keysModule, testHolder(), registryModule],
			config: {
				...kernelConfig(),
				...keysConfig(),
				"clients-registry": {
					file: paths.out,
					"publisher-key": { ...pair.publicKey.export({ format: "jwk" }), kid, alg },
					"min-version": 2,
				},
			},
			runtime: quietRuntime(),
		});
		expect((await app.get(clients).find("rp-1"))?.registered, alg).toBe(false);
		await app.stop();
		await rm(dir, { recursive: true, force: true });
		dir = "";
	}
});
