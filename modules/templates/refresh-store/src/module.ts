import { contract, defineModule, optional, probes } from "@mod/kernel";
import { familyRecords, type familyRecordsNeeds, type StoredFamilyRecord } from "@mod/refresh";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";

/** Each need refresh states, as the guarantee its space declares for it. */
const guaranteeFor: Record<keyof typeof familyRecordsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
	authenticated: "authenticated",
};
/** Families, their keys and codes, each a subject's: kept indexed by it, erased by refresh, at the tombstone's floor. */
const families: Space = {
	name: "refresh-store.families",
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "refresh",
};

/** The space's records over the phase this process reads once. */
const placed =
	contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredFamilyRecord>>>>("refresh-store.placed");

export default defineModule(
	{ name: "refresh-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => families),
		m.contribute(spaces).by(() => indexSpaceOf(families)),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredFamilyRecord>(
				{
					store: await c.get(store),
					space: families,
					index: indexSpaceOf(families),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"refresh-store",
				c.refuse,
			),
		),
		// The builder's own ports: `create`, never a raw `save` on an indexed space.
		m.provide(familyRecords).by(async (c) => {
			const builder = await c.get(placed);
			return {
				create: builder.create,
				read: builder.read,
				change: builder.change,
				erase: builder.erase,
				migrate: builder.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const builder = await c.get(placed);
			return { name: "refresh-store.phase", check: () => builder.ready() };
		}),
	],
);
