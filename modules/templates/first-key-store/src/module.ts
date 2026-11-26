import {
	firstKeyNonces,
	type firstKeyNoncesNeeds,
	firstKeyTokens,
	type firstKeyTokensNeeds,
	type Kept,
	type StoredNonce,
	type StoredToken,
} from "@mod/first-key";
import { defineModule } from "@mod/kernel";
import { type Place, recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

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
/** A first key's nonces, as first-key keys and keeps them: no subject. */
const nonces: Space = { name: "first-key-store.nonces", guarantees, subjectData: "none" };
/** Mail tokens and the mail's side's answers, as first-key keys and keeps them: each names a subject. */
const tokens: Space = {
	name: "first-key-store.tokens",
	guarantees,
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
export default defineModule({ name: "first-key-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => nonces),
	m.contribute(spaces).by(() => tokens),
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
]);
