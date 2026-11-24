import { contract, defineModule, optional, probes } from "@mod/kernel";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import { indexSpaceOf, phasedRecordsIn, subjectRecordsPhase } from "@mod/subject-records";
import {
	type ContactStore,
	contactStore,
	type contactStoreNeeds,
	type StoredContacts,
} from "@mod/users";

/** Each need users states for its contacts, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof contactStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
/** Verified contacts, one record a subject's, keyed by the subject: erased by users. */
const contacts: Space = {
	name: "users-store.contacts",
	guarantees: Object.values(guaranteeFor),
	subjectData: "online-keyed",
	erasedBy: "users",
};

/** Contacts over the one phase this process reads. */
const placed =
	contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredContacts>>>>("users-store.placed");

export default defineModule(
	{ name: "users-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => contacts),
		m.contribute(spaces).by(() => indexSpaceOf(contacts)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const place = {
				store: await c.get(store),
				space: contacts,
				index: indexSpaceOf(contacts),
				log: c.log,
				random: c.random,
			};
			return phasedRecordsIn<StoredContacts>(place, phase, "users-store", c.refuse);
		}),
		m.provide(contactStore).by(async (c): Promise<ContactStore> => {
			const records = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const records = await c.get(placed);
			return { name: "users-store.phase", check: () => records.ready() };
		}),
	],
);
