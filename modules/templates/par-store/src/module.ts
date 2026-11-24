import { defineModule } from "@mod/kernel";
import {
	type PushedRequests,
	pushedRequests,
	type pushedRequestsNeeds,
	type StoredPush,
} from "@mod/par";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need par states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof pushedRequestsNeeds, Guarantee> = {
	confirmedReads: "confirmed-reads",
	survivesFailover: "replicated",
	neverEvicted: "no-eviction",
	authenticated: "authenticated",
};
/** Pushed requests by request_uri: a client's id and its JAR's bytes, which may name a subject in its claims. */
const pushed: Space = {
	name: "par-store.pushed",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule({ name: "par-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => pushed),
	m.provide(pushedRequests).by(async (c): Promise<PushedRequests> => {
		const place = { store: await c.get(store), space: pushed, log: c.log, random: c.random };
		const records = recordsIn<StoredPush>(place);
		return {
			create: (key, record, lifetimeMs) => records.create(key, record, lifetimeMs),
			read: records.read,
		};
	}),
]);
