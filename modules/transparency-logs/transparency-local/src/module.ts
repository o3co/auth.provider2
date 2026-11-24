import { createHash } from "node:crypto";
import { defineModule, optional } from "@mod/kernel";
import { keys } from "@mod/keys";
import { passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { transparencyLog } from "@mod/transparency";
import { ceremonies, keyThumbprint } from "@mod/webauthn";
import { clientRecords, logStore } from "./contract.ts";
import { localJudging } from "./judging.ts";
import { localLog } from "./log.ts";
import { section } from "./section.ts";
import { verifiedByOne } from "./verify.ts";

// Holds nothing in process: a flow's records are in the store, each placed by one held write.
export default defineModule(
	{
		name: "transparency-local",
		section,
		replicaSafe: true,
		takes: [logStore, keys, ceremonies, passkeys, optional(clientRecords)],
	},
	(m) => [
		// The log and its judgment run in the Core: nothing outside it judges, or stops, a forged record.
		m.contribute(stances).by(() => ({
			promise: promiseNames.coreContained,
			holds: false,
			by: "transparency-local",
			reason:
				"not recommended: the log and the judgment of its records run in the Core, so a compromised Core places and judges its own records, a receiver has no receipt to check, and nothing stops its generation",
		})),
		m.provide(transparencyLog).by(async (c) => {
			const ring = await c.get(keys);
			const checking = await c.get(ceremonies);
			const held = c.late(passkeys);
			const registry = await c.getOptional(clientRecords);
			const fresh = () => Buffer.from(c.random.bytes(16)).toString("base64url");
			const generation = ring.generation();
			const s = c.section;
			return localLog({
				store: await c.get(logStore),
				writer: { instance: fresh(), generation },
				now: c.clock.now,
				id: fresh,
				judging: localJudging({
					checks: {
						// A client's evidence is verified by one key, a DPoP proof's naming no kid.
						verifyJws: (jws, keySet) =>
							ring.verifyJws(jws, keySet) ??
							(keySet.length === 1 ? verifiedByOne(jws, keySet) : undefined),
						verifyAssertion: checking.verifyAssertion,
						digest: (data) => createHash("sha256").update(data).digest("base64url"),
						keyThumbprint,
					},
					// t0 names no version and opens every preimage itself: no window, no retry to wait out.
					context: {
						ring: ring.coreRing(generation) ?? [],
						origin: s.origin,
						limits: {
							codeLifetime: s["code-lifetime"],
							refreshLifetime: s["refresh-lifetime"],
							issueWindow: s["issue-window"],
							evidenceWindow: s["evidence-window"],
							epsilon: 0,
							propagation: 0,
							retry: 0,
						},
					},
					holds: async (credential, subject) =>
						(await held().publicKeyOf(credential))?.subject === subject,
					// A client of a version its publisher signed, at the version named, as the registry holds it now.
					clientAt: async (id, version) => {
						const client = await registry?.find(id);
						if (!registry || !client || !registry.signed(client)) return undefined;
						if (registry.version(client) !== version) return undefined;
						return {
							keys: registry.keys(client),
							ceiling: (audience, scope) => registry.ceiling(client, audience, scope),
						};
					},
				}),
			});
		}),
	],
);
