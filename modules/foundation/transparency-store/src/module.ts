import { defineModule } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { frameParts, frameStore, type frameStoreNeeds, frameStoreOver } from "@mod/transparency";

/** Each need transparency states for its frames, as the guarantee the frames' space declares. */
const guaranteeFor: Record<keyof typeof frameStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** Each conditional flow's frame, under the flow's partition: kept as the log keeps the flow. */
const frames: Space = {
	name: "transparency-store.frames",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{ name: "transparency-store", replicaSafe: true, takes: [store, frameParts] },
	(m) => [
		m.contribute(spaces).by(() => frames),
		m.provide(frameStore).by(async (c) =>
			frameStoreOver({
				store: await c.get(store),
				space: frames,
				parts: await c.collect(frameParts),
				random: c.random,
				refuse: (where, reason) => c.refuse(where, reason),
			}),
		),
	],
);
