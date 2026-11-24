import { defineModule } from "@mod/kernel";
import {
	type PasskeyStore,
	passkeyPart,
	passkeyStore,
	type passkeyStoreNeeds,
	type StoredCredential,
} from "@mod/passkeys";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import type { frameStoreNeeds } from "@mod/transparency";
import { frameParts } from "@mod/transparency-frames";

/** Each need passkeys states for its credential records, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof passkeyStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
	authenticated: "authenticated",
};
/** Each need transparency states for the frames, which a part's space declares alike. */
const partGuaranteeFor: Record<keyof typeof frameStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** Credential records by credential id: its subject, kept as the log keeps the key's flow. */
const credentials: Space = {
	name: "webauthn-store.credentials",
	guarantees: Object.values(guaranteeFor),
	subjectData: "retained",
};
/** passkeys' part of each subject's flow, written by the flow's one write, as the frames are. */
const keys: Space = {
	name: "webauthn-store.keys",
	guarantees: Object.values(partGuaranteeFor),
	subjectData: "retained",
};

// Holds nothing of its own, so it is safe on many instances.
export default defineModule({ name: "webauthn-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => credentials),
	m.contribute(spaces).by(() => keys),
	m.contribute(frameParts).by(() => ({ name: passkeyPart, space: keys })),
	m.provide(passkeyStore).by(async (c): Promise<PasskeyStore> => {
		const place = { store: await c.get(store), space: credentials, log: c.log, random: c.random };
		const records = recordsIn<StoredCredential>(place);
		return {
			create: (credential, record) => records.create(credential, record, "endless"),
			read: records.read,
			change: (credential, change) => records.change(credential, change),
		};
	}),
]);
