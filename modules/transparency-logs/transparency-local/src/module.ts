import type { Checks, Context } from "@mod/authority-rules";
import { defineModule, optional } from "@mod/kernel";
import { type Jwk, keys, publicJwk } from "@mod/keys";
import { passkeys } from "@mod/passkeys";
import { promiseNames, stances } from "@mod/promises";
import { transparencyLog } from "@mod/transparency";
import { ceremonies, keyThumbprint } from "@mod/webauthn";
import { clientRecords, logStore } from "./contract.ts";
import { localJudging, localSignedJudging } from "./judging.ts";
import { localLog } from "./log.ts";
import { section } from "./section.ts";
import { digestOf, verifiedByOne, verifiedEsig } from "./verify.ts";

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
			// A key's body, its SPKI, read as keys reads a public JWK: none for a private member, another
			// spelling or no key at all.
			const bodyOf = (jwk: unknown) =>
				publicJwk(jwk as Jwk)
					?.key.export({ type: "spki", format: "der" })
					.toString("base64url");
			// V22 §B.2: no key in two sets. Here a version's keys apart, each named by a kid of its own,
			// and none the Core ring's of any generation held (kept apart as §B.2 means keys to be;
			// V18's sets join the comparison once L0 holds them).
			const ringBodies = new Set(ring.coreRings().map(bodyOf));
			const refusals = s["reset-keys"].flatMap((set) => {
				const bodies = set.keys.map(bodyOf);
				const kids = set.keys.map((k) => (typeof k.kid === "string" ? k.kid : ""));
				return bodies.flatMap((b, at) =>
					b === undefined
						? [`version ${set.version}: a key that is no public key`]
						: kids[at] === "" || kids.indexOf(kids[at] ?? "") !== at
							? [`version ${set.version}: a key with no kid of its own`]
							: bodies.indexOf(b) !== at
								? [`version ${set.version}: a key named twice`]
								: ringBodies.has(b)
									? [`version ${set.version}: a key of the Core ring`]
									: [],
				);
			});
			if (refusals.length > 0) c.refuse("transparency-local.reset-keys", refusals.join("; "));
			const sets = (version: number) =>
				s["reset-keys"].find((set) => set.version === version)?.keys ?? ("absent" as const);
			const newest = s["reset-keys"].reduce<number | undefined>(
				(most, set) => (most === undefined || set.version > most ? set.version : most),
				undefined,
			);
			const checks: Checks = {
				// A client's evidence is verified by one key, a DPoP proof's naming no kid.
				verifyJws: (jws, keySet) =>
					ring.verifyJws(jws, keySet) ??
					(keySet.length === 1 ? verifiedByOne(jws, keySet) : undefined),
				verifyAssertion: checking.verifyAssertion,
				attestedKey: checking.attestedKey,
				verifyEsig: verifiedEsig,
				digest: digestOf,
				keyThumbprint,
			};
			// t0 names no version and opens every preimage itself: no window, no retry to wait out.
			const context: Context = {
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
				...(s.installation === undefined ? {} : { reset: { installation: s.installation, sets } }),
			};
			return localLog({
				store: await c.get(logStore),
				writer: { instance: fresh(), generation },
				now: c.clock.now,
				id: fresh,
				resetting: {
					newest,
					checks,
					context,
					judging: localSignedJudging({ checks, context }),
				},
				judging: localJudging({
					checks,
					context,
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
