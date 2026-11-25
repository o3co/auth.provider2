import { defineModule } from "@mod/kernel";
import {
	firstKeyNonces,
	type firstKeyNoncesNeeds,
	firstKeyTokens,
	type firstKeyTokensNeeds,
	type Kept,
	keyChangePart,
	type StoredNonce,
	type StoredToken,
} from "@mod/passkey-management";
import { type Place, recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import type { frameStoreNeeds } from "@mod/transparency";
import { frameParts } from "@mod/transparency-frames";

/** Each need either store states, as the guarantee its space declares for it: a need of one alone left out fails the type check. */
const guaranteeFor: Record<
	keyof typeof firstKeyNoncesNeeds | keyof typeof firstKeyTokensNeeds,
	Guarantee
> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
	authenticated: "authenticated",
};
const guarantees = Object.values(guaranteeFor);
/** Each need transparency states for the frames, which a part's space declares alike. */
const partGuaranteeFor: Record<keyof typeof frameStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
	authenticated: "authenticated",
};
/** A first key's nonces, as passkey-management keys and keeps them: no subject. */
const nonces: Space = { name: "passkey-management-store.nonces", guarantees, subjectData: "none" };
/** Mail tokens and the mail's side's answers, as passkey-management keys and keeps them: each names a subject. */
const tokens: Space = {
	name: "passkey-management-store.tokens",
	guarantees,
	subjectData: "retained",
};

/** passkey-management's part of each subject's flow, written by the flow's one write, as the frames are. */
const flows: Space = {
	name: "passkey-management-store.flows",
	guarantees: Object.values(partGuaranteeFor),
	subjectData: "retained",
};

/** Records in one space, as the store interface offers them. */
function keptIn<T extends StoredNonce | StoredToken>(place: Place): Kept<T> {
	const records = recordsIn<T>(place);
	return {
		create: (key, record, lifetimeMs) => records.create(key, record, lifetimeMs),
		read: records.read,
		change: (key, change) => records.change(key, change),
	};
}

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{ name: "passkey-management-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => nonces),
		m.contribute(spaces).by(() => tokens),
		m.contribute(spaces).by(() => flows),
		m.contribute(frameParts).by(() => ({ name: keyChangePart, space: flows })),
		m.provide(firstKeyNonces).by(async (c) =>
			keptIn<StoredNonce>({
				store: await c.get(store),
				space: nonces,
				log: c.log,
				random: c.random,
			}),
		),
		m.provide(firstKeyTokens).by(async (c) =>
			keptIn<StoredToken>({
				store: await c.get(store),
				space: tokens,
				log: c.log,
				random: c.random,
			}),
		),
	],
);
