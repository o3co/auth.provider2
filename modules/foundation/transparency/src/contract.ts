import type { Changes, Finding, FlowState } from "@mod/authority-rules";
import { contract, extensionPoint } from "@mod/kernel";
import type { ResetRefusal } from "@mod/reset-wire";
import type {
	AppendAnswer,
	AppendRequest,
	Flow,
	LogRecord,
	Preimage,
} from "@mod/transparency-wire";
import type { End, Ending, Refused } from "./frame/frame.ts";

/**
 * The Core's side of the transparency log: the contract its writers take, the intent frame they
 * share (one per intent unit), the log's axis the adapters provide, and the frame's store interface.
 */

export type { End, Ending, Refused };

/** Plain JSON data, as a frame and its parts' records are kept. */
export type Json =
	| null
	| boolean
	| number
	| string
	| readonly Json[]
	| { readonly [key: string]: Json };

/** What one intent frame is the frame of (V17): a subject's flow, or one op of a client's flow. */
export type IntentUnit =
	| { readonly flow: { readonly of: "subject"; readonly id: string } }
	| { readonly flow: { readonly of: "client"; readonly id: string }; readonly op: string };

/** One of a part's records: a part is a writer's or a state owner's records, in a place its wiring binds. */
export interface PartRecord {
	readonly part: string;
	readonly name: string;
}
/** What a part record becomes in a flow's one write: a value, removed, or kept as it is (none). */
export type PartNext = { readonly value: Json } | { readonly remove: true } | undefined;

/** What a read of a unit's frame and part records saw, which the one write is held to. */
export interface FrameRead {
	readonly unit: IntentUnit;
	readonly records: readonly PartRecord[];
	readonly frame: Json | undefined;
	/** Each record's value, in the order named; none where it holds none. */
	readonly held: readonly (Json | undefined)[];
	/** The store clock's time at the read. */
	readonly now: number;
	/** On a client's op: its flow's record (its ops not yet ended), held to the write too; none on a subject's flow. */
	readonly flow?: Json | undefined;
	/** Opaque to the caller: what the frame store holds the write to. */
	readonly basis: unknown;
}

/** The frame's store interface: a unit's frame and the part records named, read, then written as one. */
export interface FrameStore {
	/** The part names bound to a place; every registration's parts are among them. */
	readonly parts: readonly string[];
	read(unit: IntentUnit, records: readonly PartRecord[]): Promise<FrameRead>;
	/** A client's flow's record, as a confirmed read; none where it holds none. */
	flowRecord(flow: IntentUnit["flow"]): Promise<Json | undefined>;
	/**
	 * A page of the client flows it holds a record of, and the cursor on; none when done. A flow
	 * whose record lives through the walk is listed. Where a frame store gives none, a client's flow
	 * is tended only as its writers ask.
	 */
	clientFlows?(cursor?: string): Promise<{
		readonly flows: readonly { readonly of: "client"; readonly id: string }[];
		readonly cursor?: string;
	}>;
	/**
	 * Writes the frame (none keeps it; `drop` removes it), on a client's op its flow's record (none
	 * keeps it), and the records as one, held to every version the read saw, refused past `deadline`
	 * on the store clock; nothing expires. Writing nothing is held to the read all the same.
	 * Unavailable means it may have applied.
	 */
	write(
		read: FrameRead,
		next: {
			readonly frame?: Json;
			readonly drop?: true;
			readonly flow?: Json;
			readonly records: readonly PartNext[];
		},
		deadline: number,
	): Promise<"written" | "moved" | "late">;
}

/** What the frame's place must be, each need a guarantee its wiring declares. */
export const frameStoreNeeds = Object.freeze({
	/** A frame dropped for room would let a second intent open on its flow. */
	neverEvicted: "never evicted",
	/** A crash losing a frame would lose an intent whose append may be on the log. */
	survivesCrash: "survives a crash",
	survivesFailover: "survives a failover",
	/** The owner rule reads another replica's owner and lease to mark or take over. */
	readsConfirmed: "reads confirmed",
	/** A frame written outside the provider would open or close an op the provider never did. */
	authenticated: "written by the provider alone",
});

/** One stage a Core writer puts on its flow: the fields it names, its preimage unsealed. */
export type Stage = Omit<
	AppendRequest,
	"v" | "prev" | "preimage" | "plaintextDigest" | "signed"
> & {
	readonly preimage: Preimage;
};
/** A record placed on a flow, with its judgment once the monitor judged it. */
export interface Placed {
	readonly record: Extract<LogRecord, { readonly position: number }>;
	readonly finding?: Finding;
	/** For a record no Core writer writes: the changes its verified body leaves. */
	readonly changes?: Changes;
}

/** What a flow holds of an op, whatever their judgments: its stages placed, its last among them, its abandonments. */
export interface OpOnFlow {
	readonly stages: number;
	/** Whether its last stage is placed (`InLogKey`). */
	readonly last: boolean;
	/** How many abandonment records of it are placed (`Abn(o, ·)`). */
	readonly abandonments: number;
}

/**
 * A reset's answer (V22 §B.6): placed, as the log answers an append (its receipt; the same
 * instruction sent again answered the same); not placed, reset-wire's `invalid` (its fault) or
 * `conflict` (the same id with another instruction); or an append's refusal the placer could not get
 * past (`temporary`, `stopped`; a `prevMismatch` it retries, never answers). Read by `result`.
 */
export type ResetAnswer = AppendAnswer | ResetRefusal;

/** The log's axis: how this Core's writer appends and reads its flows; an adapter provides it. */
export interface TransparencyLog {
	/** The writer this replica appends as: its instance, and its Core generation (`Gen(w)`). */
	readonly writer: { readonly instance: string; readonly generation: number };
	/** A preimage's plaintext digest, as its append names it. */
	digest(preimage: Preimage): string;
	/**
	 * A stage's append, its preimage sealed to the shard's monitor keys: after `prev` on a conditional
	 * flow, with none on an unconditional one (a client's).
	 */
	append(stage: Stage, prev?: number): Promise<AppendAnswer>;
	/** How many records the flow has. */
	head(flow: Flow): Promise<number>;
	/** The record at a flow's position; none where none is placed. */
	at(flow: Flow, position: number): Promise<Placed | undefined>;
	/** What the flow holds of an op, by the op ids its records name. */
	of(flow: Flow, op: string): Promise<OpOnFlow>;
	/**
	 * Places a reset boundary for an embedder's signed instruction, as the monitor does (§B.4): L0's
	 * log itself, L1's by handing it to the monitor's endpoint. Optional until every log has it.
	 */
	reset?(instruction: string): Promise<ResetAnswer>;
}

/** What two hooks hold around a bundle: its tokens' digests before its append, their signing after its receipts. */
export interface BundleSigning<P> {
	prepare(): Promise<{
		readonly prepared: P;
		readonly tokens: NonNullable<AppendRequest["tokens"]>;
	}>;
	/**
	 * The tokens signed, each carrying its receipt, before the bundle is taken in; answered only once
	 * its end is the owner's `took`, its write committed.
	 */
	sign(prepared: P, receipts: readonly string[]): Promise<readonly string[]>;
}

/** A kind of operation, registered by its writer: pure functions the driver calls. */
export interface OperationKind {
	readonly name: string;
	/** Whether its last stage is a bundle: one left alone is abandoned, never taken over. */
	readonly bundle: boolean;
	/** The parts its records are in. */
	readonly parts: readonly string[];
	/** The records its ops hold besides the frame (a reservation), read and written with it. */
	readonly records: (flow: Flow) => readonly PartRecord[];
	/** What its records become as an op ends, in the same write as the end (a confirm, a release). */
	readonly end: (
		end: { readonly op: string; readonly ending: Ending },
		held: readonly (Json | undefined)[],
	) => readonly PartNext[];
	/** For a kind that is no bundle: the stage a taker resends, the same id and content, from its records. */
	readonly resend?: (
		flow: Flow,
		op: string,
		held: readonly (Json | undefined)[],
	) => Stage | undefined;
}

/** An owner of part of a flow's state, registered by it: its records ↔ its fields of the state. Pure. */
export interface StateOwner {
	readonly name: string;
	/** The fields of the state it holds; every field is held by one owner. */
	readonly holds: readonly (keyof FlowState)[];
	readonly parts: readonly string[];
	readonly records: (flow: Flow) => readonly PartRecord[];
	/** Its fields of the state, from what its records hold. */
	readonly read: (held: readonly (Json | undefined)[]) => Partial<FlowState>;
	/** What its records become, from the state after the fold and what they held. */
	readonly write: (state: FlowState, held: readonly (Json | undefined)[]) => readonly PartNext[];
}

/**
 * The writer's part of KE-C01, on the applied state and its kind's records: the op, or why not. Its
 * `eff` is the writer's to keep equal to `effectOf` of its op's last stage's record (Eff(preimage)),
 * taken in with that record alone: an earlier stage, a start, changes nothing.
 */
export type Deciding = (
	state: FlowState,
	held: readonly (Json | undefined)[],
) =>
	| {
			readonly digest: string;
			readonly eff: Changes;
			readonly records: readonly PartNext[];
	  }
	| { readonly refused: string };

/**
 * The contract the Core's writers take: their ops on a subject flow's one intent, or each in its own
 * on a client's flow (`IntentUnit`), each write one CAS. Any other flow is refused (`notSubject`).
 */
export interface Transparency {
	/**
	 * KE-C01: decides the op on the applied state, in one write with its kind's records; never an op
	 * with a stage on the flow (again only after an empty abandonment). A writer refused `open` or `notReady` tends the flow and decides again.
	 * A client's op, holding no state, is decided on the empty state, answering the flow's head, and
	 * once, whatever its end: one with a stage or an abandonment on the flow, or closed with neither, is `ended`.
	 */
	decide(p: {
		readonly kind: string;
		readonly flow: Flow;
		readonly op: string;
		readonly decide: Deciding;
	}): Promise<
		| { readonly prev: number }
		| Refused<"notSubject" | "sealed" | "notReady" | "open" | "ended" | "moved" | "late" | string>
	>;
	/**
	 * KE-C02: the owner's stage, after `prev`; its first stage's prevMismatch closes the op. On a
	 * client's flow, appended with no previous position, `abandoned` alone closes it; any other
	 * refusal leaves it to its lease's end.
	 */
	send(p: {
		readonly flow: Flow;
		readonly op: string;
		readonly stage: Stage;
		readonly prev: number;
	}): Promise<
		{ readonly answer: AppendAnswer; readonly end?: End } | Refused<"notSubject" | "notOwner">
	>;
	/**
	 * The owner, the flow taken in to its head, re-checks its op there: moves its prev, or closes it.
	 * `recheck` is pure, on the state alone. An op with no stage placed is refused (`unplaced`).
	 */
	rebase(p: {
		readonly flow: Flow;
		readonly op: string;
		readonly recheck: (state: FlowState) => boolean;
	}): Promise<
		| { readonly prev: number }
		| { readonly end: End }
		| Refused<"notSubject" | "notOwner" | "notReady" | "unplaced" | "moved" | "late">
	>;
	/**
	 * KE-C04: takes in the next record; `own`: the caller owns that op and is in its apply phase (on a
	 * client's flow, the op whose own next record it takes in, past any other). An
	 * end the owner gives output for (`owner`, `took`) is answered once its write committed. A replica
	 * with no registration of the open intent's kind takes in nothing (`stuck`).
	 */
	step(p: {
		readonly flow: Flow;
		readonly own?: string;
	}): Promise<
		| { readonly position: number; readonly end?: End }
		| Refused<
				| "notSubject"
				| "atHead"
				| "unjudged"
				| "sealed"
				| "notNext"
				| "waits"
				| "stuck"
				| "moved"
				| "late"
		  >
	>;
	/**
	 * An idle replica's turn on a flow: takes it in to its head, claims an orphan, sends an abandonment;
	 * on a client's flow, so for the next open ops its record lists, going round them turn by turn.
	 */
	tend(flow: Flow): Promise<
		| {
				readonly stepped: number;
				readonly did?: "marked" | "tookOver" | "abandonment";
				readonly answer?: AppendAnswer;
		  }
		| Refused<"notSubject">
	>;
	/**
	 * Hands an embedder's reset instruction to the log's axis, answering what it answered; `unsupported`
	 * where the log has no reset. The boundary is taken in as any monitor's record, by `step` or `tend`.
	 */
	reset(p: {
		readonly instruction: string;
	}): Promise<{ readonly answer: ResetAnswer } | Refused<"unsupported">>;
	/**
	 * A change of a kind's records held to the frame: only while the flow has no open intent. A kind's
	 * owner changes them so alone, never in the store directly.
	 */
	changeHeld(p: {
		readonly kind: string;
		readonly flow: Flow;
		readonly records: readonly PartRecord[];
		readonly change: (held: readonly (Json | undefined)[]) => readonly PartNext[];
	}): Promise<{ readonly changed: true } | Refused<"notSubject" | "open" | "moved" | "late">>;
}

export const transparency = contract<Transparency>("transparency");
/** The log's axis, which an adapter provides. */
export const transparencyLog = contract<TransparencyLog>("transparency.log");
/** The frame's store interface, which a store wiring provides. */
export const frameStore = contract<FrameStore>("transparency.frame-store");

/** The kinds of operation, keyed by name. */
export const operationKinds = extensionPoint<OperationKind>("transparency.operation-kinds", {
	multiplicity: "keyed",
	keyOf: (kind) => kind.name,
});
/** The owners of a flow's state, keyed by name. */
export const stateOwners = extensionPoint<StateOwner>("transparency.state-owners", {
	multiplicity: "keyed",
	keyOf: (owner) => owner.name,
});
