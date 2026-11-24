import { createHash } from "node:crypto";
import { defineModule } from "@mod/kernel";
import { keys } from "@mod/keys";
import { passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { transparencyLog } from "@mod/transparency";
import { ceremonies } from "@mod/webauthn";
import { logStore } from "./contract.ts";
import { localJudging } from "./judging.ts";
import { localLog } from "./log.ts";
import { section } from "./section.ts";

// Holds nothing in process: a flow's records are in the store, each placed by one held write.
export default defineModule(
	{
		name: "transparency-local",
		section,
		replicaSafe: true,
		takes: [logStore, keys, ceremonies, passkeys],
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
						verifyJws: (jws, keySet) => ring.verifyJws(jws, keySet),
						verifyAssertion: checking.verifyAssertion,
						digest: (data) => createHash("sha256").update(data).digest("base64url"),
					},
					// t0 names no version and opens every preimage itself: no window, no retry to wait out.
					context: {
						ring: ring.coreRing(generation) ?? [],
						origin: s.origin,
						limits: {
							codeLifetime: s["code-lifetime"],
							refreshLifetime: s["refresh-lifetime"],
							issueWindow: s["issue-window"],
							epsilon: 0,
							propagation: 0,
							retry: 0,
						},
					},
					holds: async (credential, subject) =>
						(await held().publicKeyOf(credential))?.subject === subject,
				}),
			});
		}),
	],
);
