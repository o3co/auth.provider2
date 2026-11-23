import {
	abandonedFamily,
	type Changes,
	type Finding,
	type RecordKind,
	ruleSchemas,
} from "@mod/authority-rules";
import { opIds, type Writer } from "@mod/transparency-wire";
import { z } from "zod";

/** The intent frame's pure core (kernel-spec §5.1): each write it answers is one CAS of the frame read. */

export const intentStates = ["pending", "abandoning", "done", "closed"] as const;
export type IntentState = (typeof intentStates)[number];

/** A flow's one intent (`it[f]`). */
export interface Intent {
	readonly op: string;
	readonly kind: string;
	readonly state: IntentState;
	/** The applied position it was decided on: its first stage's previous position. */
	readonly prev: number;
	/** `ptd`. */
	readonly digest: string;
	/** `eff`, none once it ended. */
	readonly eff: Changes | null;
	readonly by: string;
	/** Store-clock ms the lease holds before; past it, the intent stays and has no owner. */
	readonly leaseEnd: number;
	readonly generation: number;
	/** The family the op's bundle, taken in, made or rotated: what its abandonment drops. */
	readonly family: string | null;
	/** Whether its owner took it over (KE-C10): that replica's tending is then its apply phase. */
	readonly taken: boolean;
}

/** A flow's frame: its applied position (`cs[f].ap`), the generation that sealed it (`cs[f].g`), its intent. */
export interface Frame {
	readonly applied: number;
	readonly generation: number;
	readonly intent: Intent | null;
}

/** Who reads the frame: the replica, its Core generation, and the store clock's time of the read. */
export interface At {
	readonly replica: string;
	readonly generation: number;
	readonly now: number;
}

/**
 * How an op ended: its last stage took, did not (a noEffect not held, however judged, too), was held;
 * its abandonment closed it; its owner refused it.
 */
export type Ending = "took" | "didNotTake" | "held" | "abandoned" | "refused";
/** An op's end, and whether its live owner ended it, so that owner alone gives its output. */
export interface End {
	readonly op: string;
	readonly kind: string;
	readonly ending: Ending;
	readonly owner: boolean;
}

export interface Taken {
	readonly id: string;
	readonly role: Writer["role"];
	readonly kind: RecordKind;
	readonly op: string;
	readonly last: boolean;
	readonly position: number;
	readonly abandons?: { readonly op: string; readonly attempt: number };
	readonly finding: Finding;
	/** Another writer's: the changes its verified body leaves. */
	readonly changes?: Changes;
}

/** Why an event writes nothing. */
export type Refused<W extends string> = { readonly refused: W };
/** A write of the frame; an owner's is held to commit before its lease ends (`ownerUntil`, store clock). */
export interface Written {
	readonly frame: Frame;
	readonly ownerUntil?: number;
	readonly end?: End;
}

const count = z.number().int().nonnegative();
const intent = z
	.object({
		op: z.string().min(1),
		kind: z.string().min(1),
		state: z.enum(intentStates),
		prev: count,
		digest: z.string().min(1),
		eff: ruleSchemas.changes.nullable(),
		by: z.string().min(1),
		leaseEnd: count,
		generation: z.number().int().positive(),
		family: z.string().min(1).nullable(),
		taken: z.boolean(),
	})
	.strict();
const frame = z
	.object({ applied: count, generation: z.number().int().positive(), intent: intent.nullable() })
	.strict();

/** The frame a stored value holds; none yet is a flow with nothing applied, sealed by `generation`. */
export function frameOf(value: unknown, generation: number): Frame {
	if (value === undefined) return { applied: 0, generation, intent: null };
	const read = frame.safeParse(value);
	if (!read.success) throw new TypeError(`a stored frame of another shape: ${read.error.message}`);
	return read.data as Frame;
}

/** SealedOK: the frame was written by the reader's generation. */
export const sealed = (f: Frame, at: At) => f.generation === at.generation;
/** It(w, f): the intent, unless another generation sealed it. */
export const intentOf = (f: Frame, at: At) =>
	f.intent !== null && f.intent.generation === at.generation ? f.intent : null;
export const isOpen = (i: Intent | null) => i?.state === "pending" || i?.state === "abandoning";
/** Owner(w, I) ≜ pending ∧ by = w ∧ lease, the lease judged on the store clock. */
export const isOwner = (i: Intent | null, at: At) =>
	i?.state === "pending" && i.by === at.replica && at.now < i.leaseEnd;
/** Orphan(w, I) ≜ pending ∧ ¬lease. */
export const isOrphan = (i: Intent | null, at: At) =>
	i?.state === "pending" && at.now >= i.leaseEnd;

const ended = (i: Intent, state: "done" | "closed"): Intent => ({ ...i, state, eff: null });
/** The last store-clock ms an owner's write may commit at: before its lease ends. */
const until = (i: Intent) => i.leaseEnd - 1;

/**
 * KE-C01: the op's intent, decided on the applied state, when the flow is ready and has none open,
 * and the flow holds no last stage of the op (`placed`, read from the log).
 */
export function decided(
	f: Frame,
	at: At,
	p: {
		readonly op: string;
		readonly kind: string;
		readonly digest: string;
		readonly eff: Changes;
		readonly head: number;
		readonly placed: { readonly last: boolean };
		readonly leaseMs: number;
	},
): Written | Refused<"sealed" | "notReady" | "open" | "ended"> {
	if (!sealed(f, at)) return { refused: "sealed" };
	if (f.applied !== p.head) return { refused: "notReady" };
	const it = intentOf(f, at);
	if (isOpen(it)) return { refused: "open" };
	if (p.placed.last) return { refused: "ended" };
	const next: Intent = {
		op: p.op,
		kind: p.kind,
		state: "pending",
		prev: f.applied,
		digest: p.digest,
		eff: p.eff,
		by: at.replica,
		leaseEnd: at.now + p.leaseMs,
		generation: at.generation,
		family: null,
		taken: false,
	};
	return { frame: { ...f, intent: next } };
}

/** The owner closes its op without a record: its own stage's refusal is final (prevMismatch, a re-check). */
export function closedByOwner(
	f: Frame,
	at: At,
	op: string,
): (Written & { readonly end: End }) | Refused<"notOwner"> {
	const it = intentOf(f, at);
	if (!it || !isOwner(it, at) || it.op !== op) return { refused: "notOwner" };
	return {
		frame: { ...f, intent: ended(it, "closed") },
		ownerUntil: until(it),
		end: { op, kind: it.kind, ending: "refused", owner: true },
	};
}

/** The owner, its re-check passed on the flow taken in to its head, sends its next stage after it. */
export function rebased(
	f: Frame,
	at: At,
	op: string,
	head: number,
): Written | Refused<"notOwner" | "notReady"> {
	const it = intentOf(f, at);
	if (!it || !isOwner(it, at) || it.op !== op) return { refused: "notOwner" };
	if (f.applied !== head) return { refused: "notReady" };
	return { frame: { ...f, intent: { ...it, prev: head } }, ownerUntil: until(it) };
}

/** KE-C14: an orphan, the flow taken in to its head, is marked abandoning by the marker. */
export function marked(
	f: Frame,
	at: At,
	head: number,
): Written | Refused<"sealed" | "notReady" | "notOrphan"> {
	if (!sealed(f, at)) return { refused: "sealed" };
	if (f.applied !== head) return { refused: "notReady" };
	const it = intentOf(f, at);
	if (!it || !isOrphan(it, at)) return { refused: "notOrphan" };
	return { frame: { ...f, intent: { ...it, state: "abandoning", by: at.replica } } };
}

/** KE-C10: an orphan that is no bundle is taken over, with a lease of the taker's (a bundle never is). */
export function takenOver(
	f: Frame,
	at: At,
	p: { readonly leaseMs: number; readonly bundle: (kind: string) => boolean },
): Written | Refused<"sealed" | "notOrphan" | "bundle"> {
	if (!sealed(f, at)) return { refused: "sealed" };
	const it = intentOf(f, at);
	if (!it || !isOrphan(it, at)) return { refused: "notOrphan" };
	if (p.bundle(it.kind)) return { refused: "bundle" };
	const next = { ...it, by: at.replica, leaseEnd: at.now + p.leaseMs, taken: true };
	return { frame: { ...f, intent: next } };
}

/**
 * KE-C09: the abandonment record of the abandoning op, after the head the same read shows; its
 * attempt is one past the op's abandonment records on the flow (`placed`, read from the log).
 */
export function abandonStage(
	f: Frame,
	at: At,
	head: number,
	placed: { readonly abandonments: number },
):
	| {
			readonly op: string;
			readonly abandons: { readonly op: string; readonly attempt: number; readonly digest: string };
			readonly prev: number;
	  }
	| Refused<"sealed" | "notReady" | "notAbandoning"> {
	if (!sealed(f, at)) return { refused: "sealed" };
	const it = intentOf(f, at);
	if (it?.state !== "abandoning") return { refused: "notAbandoning" };
	if (f.applied !== head) return { refused: "notReady" };
	const attempt = placed.abandonments + 1;
	return {
		op: opIds.abandonment(it.op, attempt),
		abandons: { op: it.op, attempt, digest: it.digest },
		prev: f.applied,
	};
}

/** Whether a change held to the frame may go through: the flow has no open intent. */
export function whileClosed(f: Frame, at: At): { readonly closed: true } | Refused<"open"> {
	return isOpen(intentOf(f, at)) ? { refused: "open" } : { closed: true };
}

const acceptable = (j: Finding) =>
	(j.verdict === "verified" || j.verdict === "unsupported") && j.outcome === "took";
/** How a last stage ends its op: a noEffect reports the op did not take, however it is judged. */
const endingOf = (r: Taken): Ending => {
	if (r.finding.verdict === "held") return "held";
	return r.kind !== "noEffect" && acceptable(r.finding) ? "took" : "didNotTake";
};

/**
 * KE-C04: takes in the record at the applied position's next, by the end-of-intent table. The
 * changes are the fold's `e` (§6.3, the callers' contract 1). `own`: the caller is the owner in its
 * apply phase, the only one that takes in a live owner's last stage.
 */
export function stepped(
	f: Frame,
	at: At,
	r: Taken,
	p: { readonly own: boolean; readonly bundle: (kind: string) => boolean },
): (Written & { readonly changes: Changes }) | Refused<"sealed" | "notNext" | "waits" | "stuck"> {
	if (!sealed(f, at)) return { refused: "sealed" };
	if (r.position !== f.applied + 1) return { refused: "notNext" };
	const advanced = (intent: Intent | null) => ({
		applied: r.position,
		generation: at.generation,
		intent,
	});
	// Another writer's record: any replica, the intent unchanged.
	if (r.role !== "core") return { frame: advanced(f.intent), changes: r.changes ?? {} };
	const it = intentOf(f, at);
	const abandonment = r.kind === "abandonment";
	const ofIt = abandonment ? r.abandons?.op === it?.op : r.op === it?.op;
	// A Core record of no open intent is taken in by no one (OfIt).
	if (!it || !isOpen(it) || !ofIt) return { refused: "stuck" };
	const held = !abandonment && it.state === "pending" && at.now < it.leaseEnd;
	if (held && (it.by !== at.replica || (r.last && !p.own))) return { refused: "waits" };
	const owned = held ? { ownerUntil: until(it) } : {};
	const took = acceptable(r.finding);
	if (abandonment) {
		const changes: Changes = it.family === null ? {} : { abandon: it.family };
		if (!took) return { frame: advanced(it), changes };
		const end: End = { op: it.op, kind: it.kind, ending: "abandoned", owner: false };
		return { frame: advanced(ended(it, "closed")), changes, end };
	}
	const changes = r.kind === "noEffect" ? {} : (it.eff ?? {});
	if (!r.last) return { frame: advanced(it), changes, ...owned };
	const ending = endingOf(r);
	const end: End = { op: it.op, kind: it.kind, ending, owner: held };
	if (p.bundle(it.kind) && !held) {
		// A bundle left alone is abandoned, never delivered; an abandoning op stays so (A40).
		const by = it.state === "pending" ? at.replica : it.by;
		const family = abandonedFamily({ envelope: r, changes }) ?? null;
		const left = { ...it, state: "abandoning" as const, by, family };
		return { frame: advanced(left), changes };
	}
	const state = ending === "took" ? "done" : "closed";
	return { frame: advanced(ended(it, state)), changes, end, ...owned };
}
