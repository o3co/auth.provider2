import {
	type JarReservations,
	jarReservations,
	type jarReservationsNeeds,
	type StoredReservation,
} from "@mod/authorize";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need authorize states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof jarReservationsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
	authenticated: "authenticated",
};
/** JAR reservations by client and `jti`: a digest and the statement its start answered, no subject. */
const reservations: Space = {
	name: "authorize-store.reservations",
	guarantees: Object.values(guaranteeFor),
	subjectData: "none",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule({ name: "authorize-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => reservations),
	m.provide(jarReservations).by(async (c): Promise<JarReservations> => {
		const place = { store: await c.get(store), space: reservations, log: c.log, random: c.random };
		const records = recordsIn<StoredReservation>(place);
		return {
			create: (key, record, lifetimeMs) => records.create(key, record, lifetimeMs),
			read: records.read,
			change: (key, change) => records.change(key, change),
		};
	}),
]);
