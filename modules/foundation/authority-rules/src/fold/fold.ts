import type { recordKinds, StageOutcome, Verdict } from "@mod/transparency-wire";
import { z } from "zod";

/** The kinds a flow's record may be, by any writer role but the log's. */
export type RecordKind = Exclude<
	(typeof recordKinds)[keyof typeof recordKinds][number],
	(typeof recordKinds.log)[number]
>;

/** A record's verdict and outcome, the fold's `j`. */
export interface Finding {
	readonly verdict: Verdict;
	readonly outcome: StageOutcome;
}

/** The envelope fields the fold reads (`Env(r)`), with the record's id, which names what it makes. */
export interface Envelope {
	readonly id: string;
	readonly kind: RecordKind;
	readonly op: string;
	readonly stage: number;
	readonly last: boolean;
	readonly position: number;
	readonly acceptedAt: number;
}

const id = z.string().min(1);
const count = z.number().int().nonnegative();
/** The registration records from the root first-trust key down to the item's own key. */
const chain = z.array(id);
const placed = { position: z.number().int().positive(), acceptedAt: count };

/**
 * Items by id, read entry by entry so every own key stays one, `__proto__` too (a record id the log
 * may give): a plain record schema would drop it, and the state read back would differ from the fold's.
 */
const items = <T extends z.ZodType>(item: T) =>
	z.preprocess(
		(v) => (v !== null && typeof v === "object" && !Array.isArray(v) ? Object.entries(v) : null),
		z
			.array(z.tuple([id, item]))
			.transform((entries) => Object.fromEntries(entries) as Record<string, z.output<T>>),
	);

/** A flow's state, the fold's `S`: the live items by the id of the record that made each. */
export const flowState = z
	.object({
		/** The key generation: the boundaries (erasure boundaries) folded so far. */
		keyGeneration: count,
		keys: items(z.object({ credential: id, publicKey: id, chain, ...placed }).strict()),
		approvals: items(z.object({ chain, code: id, client: id, ...placed }).strict()),
		/** A family by the id of the bundle that made it; `rotation` counts its rotations. */
		families: items(
			z.object({ approval: id, chain, client: id, rotation: count, ...placed }).strict(),
		),
		/** The use-once marks (a statement, a code): set by an op's last stage, never taken off. */
		consumed: z.array(id),
	})
	.strict();

/** A record's changes, the fold's `e`: what its writer left (a Core writer's intent, another's body). */
export const changes = z
	.object({
		/** A key registered; `by` names the key whose approval added it, none for first trust. */
		key: z.object({ credential: id, publicKey: id, by: id.optional() }).strict().optional(),
		removeKey: id.optional(),
		approval: z.object({ key: id, code: id, client: id }).strict().optional(),
		/** A family made from the approval's code. */
		family: z.object({ approval: id }).strict().optional(),
		/** The family a refresh rotates. */
		rotate: id.optional(),
		consume: z.array(id).optional(),
		/** A denial's registration record. */
		revoke: id.optional(),
		/** The family an abandonment drops: the one the abandoned op's bundle made or rotated. */
		abandon: id.optional(),
	})
	.strict();

export type FlowState = z.infer<typeof flowState>;
export type Changes = z.infer<typeof changes>;

/** One judged position of a flow: what the rules read of its record, and its judgment. */
export interface FlowEntry {
	readonly envelope: Envelope;
	readonly changes: Changes;
	readonly judgment: Finding;
	/** What the record names as its parent (a Core record's preimage, a confirmation's or denial's registration). */
	readonly parent?: string | undefined;
	/** How a start or a bundle roots: an approval's code, a family's refresh or a client, where its preimage was read. */
	readonly via?: "code" | "refresh" | "client" | undefined;
	/**
	 * A client's start: the evidence elements it names, the registry version it names, and the
	 * thumbprint of the key its evidence was read by, where read.
	 */
	readonly client?:
		| {
				readonly elements: readonly string[];
				readonly version?: number | undefined;
				readonly key?: string | undefined;
		  }
		| undefined;
}

/** The state before a flow's first record. */
export const emptyState: FlowState = Object.freeze({
	keyGeneration: 0,
	keys: Object.freeze({}),
	approvals: Object.freeze({}),
	families: Object.freeze({}),
	consumed: Object.freeze([]) as unknown as string[],
});

/** The state's item of an id, its own entry alone: an inherited name (`toString`, `__proto__`) is none. */
export const own = <T>(items: Readonly<Record<string, T>>, id: string): T | undefined =>
	Object.hasOwn(items, id) ? items[id] : undefined;

/** Whether a verdict lets a record be received: verified or unsupported. */
export const acceptable = (verdict: Verdict) => verdict === "verified" || verdict === "unsupported";

/**
 * The family an abandonment of a bundle's op drops, from the bundle's envelope and its changes: the
 * one it made (named by its record's id, as the fold names it) or rotated; none for any other record.
 * The Core's intent and the monitor's Eff of the abandonment both take it from here.
 */
export function abandonedFamily(bundle: {
	readonly envelope: Pick<Envelope, "id" | "kind">;
	readonly changes: Changes;
}): string | undefined {
	if (bundle.envelope.kind !== "bundle") return undefined;
	return bundle.changes.family ? bundle.envelope.id : bundle.changes.rotate;
}

type Item = { readonly chain: readonly string[] };
const under = (itemId: string, item: Item, x: string) => itemId === x || item.chain.includes(x);
const keep = <T extends Item>(items: Readonly<Record<string, T>>, x: string) =>
	Object.fromEntries(Object.entries(items).filter(([k, item]) => !under(k, item, x)));

/** The state without `x` and everything rooted at it: Revoke, the rule a denial takes. */
function withoutRooted(s: FlowState, x: string): FlowState {
	return {
		...s,
		keys: keep(s.keys, x),
		approvals: keep(s.approvals, x),
		families: keep(s.families, x),
	};
}

/**
 * DelDrop (V24, owner (a)): the state without the key `x` and the families whose root key (their
 * chain's last) it is. The keys it approved and its approvals stay. None of `x`, no change.
 */
function withoutKey(s: FlowState, x: string): FlowState {
	if (!own(s.keys, x)) return s;
	const { [x]: _deleted, ...keys } = s.keys;
	const families = Object.fromEntries(
		Object.entries(s.families).filter(([, family]) => family.chain.at(-1) !== x),
	);
	return { ...s, keys, families };
}

/** NextGen: the key generation moves on; every key, approval and family of the old one goes. */
const nextGeneration = (s: FlowState): FlowState => ({
	...emptyState,
	keyGeneration: s.keyGeneration + 1,
	consumed: s.consumed,
});

/** UpdRec: an op's last stage adds its changes; an earlier stage changes nothing (OI-03). */
function update(s: FlowState, k: Envelope, e: Changes): FlowState {
	if (!k.last) return s;
	const at = { position: k.position, acceptedAt: k.acceptedAt };
	let next = s;
	if (e.key) {
		const by = e.key.by === undefined ? undefined : own(next.keys, e.key.by);
		if (e.key.by === undefined || by) {
			const keyChain = by && e.key.by ? [...by.chain, e.key.by] : [];
			const key = {
				credential: e.key.credential,
				publicKey: e.key.publicKey,
				chain: keyChain,
				...at,
			};
			next = { ...next, keys: { ...next.keys, [k.id]: key } };
		}
	}
	if (e.removeKey !== undefined) next = withoutKey(next, e.removeKey);
	if (e.approval) {
		const key = own(next.keys, e.approval.key);
		if (key) {
			const approval = {
				chain: [...key.chain, e.approval.key],
				code: e.approval.code,
				client: e.approval.client,
				...at,
			};
			next = { ...next, approvals: { ...next.approvals, [k.id]: approval } };
		}
	}
	if (e.family) {
		const approval = own(next.approvals, e.family.approval);
		if (approval) {
			const family = {
				approval: e.family.approval,
				chain: approval.chain,
				client: approval.client,
				rotation: 0,
				...at,
			};
			next = { ...next, families: { ...next.families, [k.id]: family } };
		}
	}
	const rotated = e.rotate === undefined ? undefined : own(next.families, e.rotate);
	if (rotated && e.rotate !== undefined) {
		const family = { ...rotated, rotation: rotated.rotation + 1 };
		next = { ...next, families: { ...next.families, [e.rotate]: family } };
	}
	const marks = (e.consume ?? []).filter(
		(m, i, all) => !next.consumed.includes(m) && all.indexOf(m) === i,
	);
	if (marks.length > 0) next = { ...next, consumed: [...next.consumed, ...marks] };
	return next;
}

/**
 * The one fold (kernel-spec §6.3, PR-ONE-FOLD): what one record does to its flow's state, from the
 * state, its envelope, its changes and its judgment. The Core's take-in, the monitor's stateOf and a
 * rebuild call it alike; it reads no record bytes.
 */
export function fold(state: FlowState, envelope: Envelope, e: Changes, j: Finding): FlowState {
	if (!(acceptable(j.verdict) && j.outcome === "took")) return state;
	switch (envelope.kind) {
		case "denial":
			return e.revoke === undefined ? state : withoutRooted(state, e.revoke);
		case "abandonment": {
			if (e.abandon === undefined || !own(state.families, e.abandon)) return state;
			const { [e.abandon]: _dropped, ...families } = state.families;
			return { ...state, families };
		}
		case "erasureBoundary":
		case "resetBoundary":
			return nextGeneration(state);
		case "confirmation":
		case "tombstone":
			return state;
		default:
			return update(state, envelope, e);
	}
}
