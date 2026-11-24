import { readFile } from "node:fs/promises";
import { clientSources } from "@mod/clients";
import { defineModule } from "@mod/kernel";
import { keys } from "@mod/keys";
import { promiseNames, stances } from "@mod/promises";
import { publisherKeyFits, recordOf, versionOf } from "./reading.ts";
import { section } from "./section.ts";

// Safe on many instances given the same file on each: it holds only what it read at boot.
export default defineModule(
	{ name: "clients-registry", replicaSafe: true, section, takes: [keys] },
	(m) => [
		m.contribute(clientSources).by(async (c) => {
			if (!publisherKeyFits(c.section["publisher-key"])) {
				c.refuse(
					"clients-registry.publisher-key",
					"is no public JWK with a kid and an alg, EdDSA over Ed25519 or ES256 over P-256, that may verify signatures",
				);
			}
			const text = await readFile(c.section.file, "utf8").catch(() => undefined);
			if (text === undefined) {
				return c.refuse(
					"clients-registry.file",
					"not readable: write the path of the signed version",
				);
			}
			const read = versionOf(text, c.section, (await c.get(keys)).verifyJws);
			if ("refused" in read) return c.refuseAll([read.refused]);
			const { version } = read;
			const records = new Map(
				version.clients.map((client) => [client.id, recordOf(client, version.version)]),
			);
			c.onStart(() => {
				c.log.info("clients-registry.read", {
					version: version.version,
					clients: records.size,
				});
			});
			// Every record is of the version verified under publisher-key above.
			const listed = [...records.values()];
			return { signed: true, find: async (id) => records.get(id), listed: async () => listed };
		}),
		m.contribute(stances).by(() => ({
			promise: promiseNames.coreContained,
			holds: false,
			by: "clients-registry",
			setting: "clients-registry.file",
			reason:
				"a version reaches the Core as a file it reads at boot, not on the log's publisher flow, so no one outside can check which version the Core answered by",
		})),
	],
);
