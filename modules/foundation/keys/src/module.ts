import { contract, defineModule } from "@mod/kernel";
import { accessTokenSigning, type KeyHolder, keys, type Ring } from "./contract.ts";
import { keyHolders } from "./holder.ts";
import { rs256Deprecated } from "./material/public.ts";
import { coreJwks, publish } from "./publishing/publishing.ts";
import { verifiedBy } from "./rings/given.ts";
import { type Rings, readRings } from "./rings/ring.ts";
import { rs256Named } from "./rings/section.ts";
import { refusingAccessTokens, ringSigner } from "./rings/signer.ts";
import { sealing } from "./sealing/sealing.ts";
import { section } from "./section.ts";

const held = contract<Rings & { readonly holder: KeyHolder }>("keys.rings");

// Safe on many instances given the same keys on each (deployment-guarantees, Several instances).
export default defineModule(
	{ name: "keys", replicaSafe: true, section, takes: [keyHolders] },
	(m) => [
		m.provide(held).by(async (c) => {
			const [holder] = (await c.collect(keyHolders)) as [KeyHolder];
			const read = readRings(c.section, holder);
			if ("refused" in read) return c.refuseAll(read.refused);
			// The operator's choice, yet said at every start, as RS256 is weaker and outside FAPI 2.0.
			const rs256 = rs256Named(c.section);
			if (rs256.length > 0)
				c.log.warn("keys.rs256_deprecated", { keys: rs256.join(" "), reason: rs256Deprecated });
			return { ...read, holder };
		}),
		m.provide(keys).by(async (c) => {
			const rings = await c.get(held);
			const signerOf = (name: Ring, ring: Rings[Ring]) =>
				ringSigner(name, ring, rings.holder, c.clock.now, c.log);
			const signers = {
				authority: signerOf("authority", rings.authority),
				core: signerOf("core", rings.core),
			};
			// Each generation's key verifies alone, apart from the ring's current one.
			const ofGeneration = new Map(
				[...rings.core.generations].map(([generation, key]) => [
					generation,
					signerOf("core", { signing: key, verifying: [key] }),
				]),
			);
			return {
				prepare: (ring, typ) => {
					refusingAccessTokens(typ);
					return signers[ring].prepare(typ);
				},
				sign: (prepared, payload) => signers[prepared.ring].sign(prepared, payload),
				verify: async (ring, token, typ) => {
					refusingAccessTokens(typ);
					return signers[ring].verify(token, typ);
				},
				verifyOf: async (generation, token, typ) => {
					refusingAccessTokens(typ);
					const signer = ofGeneration.get(generation);
					return signer ? signer.verify(token, typ) : { kind: "invalid", reason: "kid_unknown" };
				},
				generation: () => rings.core.generation,
				coreRing: (generation) => coreJwks(rings, generation),
				verifyJws: (jws, given) => verifiedBy(jws, given),
				algorithm: (ring) => rings[ring].signing.alg,
				nextAlgorithm: (ring) => rings[ring].next?.alg,
				...sealing(rings.holder, rings.sealing, c.random, c.log),
				powers: () => ({ ...rings.holder.powers }),
				publish: (args) => publish(rings, c.clock.now(), args),
			};
		}),
		m.provide(accessTokenSigning).by(async (c) => {
			const rings = await c.get(held);
			const signer = ringSigner("authority", rings.authority, rings.holder, c.clock.now, c.log);
			return {
				prepare: () => signer.prepare("at+jwt"),
				sign: (prepared, payload) => signer.sign(prepared, payload),
				verify: (token) => signer.verify(token, "at+jwt"),
			};
		}),
	],
);
