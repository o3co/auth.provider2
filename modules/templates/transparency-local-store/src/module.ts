import { defineModule } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { logStore, type logStoreNeeds, logStoreOver } from "@mod/transparency-local";

/** Each need transparency-local states for its log, as the guarantee the log's space declares. */
const guaranteeFor: Record<keyof typeof logStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** Each flow's records, under the flow's words: kept as a log keeps its flows, with no expiry. */
const log: Space = {
	name: "transparency-local-store.log",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{ name: "transparency-local-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => log),
		m.provide(logStore).by(async (c) =>
			logStoreOver({
				store: await c.get(store),
				space: log,
				random: c.random,
				where: "transparency-local-store",
				refuse: (where, reason) => c.refuse(where, reason),
			}),
		),
	],
);
