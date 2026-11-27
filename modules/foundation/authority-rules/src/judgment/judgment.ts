import {
	type LogRecord,
	recordKinds,
	type StageOutcome,
	schemas,
	type Verdict,
} from "@mod/transparency-wire";
import {
	type Ask,
	clientOf,
	codeStartedBefore,
	effectOf,
	refusalOf,
	rootOf,
	timely,
	uncheckedOf,
} from "../chain/chain.ts";
import type { ClientAt } from "../client/client.ts";
import { type Checks, type Context, isCoreKind, readPreimage } from "../evidence/evidence.ts";
import { acceptable, type Changes, type FlowEntry, type FlowState } from "../fold/fold.ts";
import { type ResetFinding, resetFinding } from "../reset/reset.ts";

/** A placed record of a flow: any but the log's tick. */
export type FlowRecord = Exclude<LogRecord, { kind: "tick" }>;

/** What opening a Core writer's preimage gave the monitor. */
export type Opening =
	/** Decrypted with its key, its plaintext digest the envelope's: the preimage as read (not yet held to a schema). */
	| { readonly opened: unknown }
	/** The ciphertext's hash held and the key was usable, yet it did not decrypt or verify (J4). */
	| { readonly undecryptable: true }
	/** The store's ciphertext is damaged or lost (J5). */
	| { readonly missing: "damaged" | "lost" }
	/** Fetching it or using the key fails for now, since a time (J1, J6); `now` is the caller's clock. */
	| { readonly failing: { readonly since: number; readonly now: number } };

/** A version's acceptance time b(v), and the next one's b(v+1) where it is known. */
export interface Window {
	readonly at: number;
	readonly next?: number | undefined;
}

/** One record as the monitor read it, to be judged on its flow's judged prefix. */
export interface Reading {
	readonly record: FlowRecord;
	/** A Core writer's record: what opening its preimage gave. */
	readonly opening?: Opening | undefined;
	/** Another writer's record: its signed body, as its signature verified. */
	readonly body?: unknown;
	/** The monitor key ids ever in a key set, and those of the set the log checked the record against. */
	readonly keySets?:
		| { readonly ever: readonly string[]; readonly atRecord: readonly string[] }
		| undefined;
	/** The windows of the versions the record names. */
	readonly versions?: { readonly registry?: Window; readonly config?: Window } | undefined;
	/** A client's start: its client's record at the registry version it names, null where it names none (`Ask`). */
	readonly client?: ClientAt | null | undefined;
	readonly state: FlowState;
	readonly prior: readonly FlowEntry[];
	readonly checks: Checks;
	readonly context: Context;
}

/** The rows of the judgment table (kernel-spec §6.1). */
export type Row = `J${0 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13}` | "J0r";

/** A record's judgment: its flow entry and the row that gave it, or why the monitor waits (J1, WaitVer). */
export type Ruling =
	| { readonly wait: "temporary" | "version" }
	| {
			readonly entry: FlowEntry;
			readonly row: Row;
			/** Counted toward its writer's hold limit (A46). */
			readonly counted: boolean;
			readonly reason?: string;
	  };

const askOf = (reading: Reading, preimage: unknown): Ask => ({
	record: reading.record,
	preimage,
	state: reading.state,
	prior: reading.prior,
	checks: reading.checks,
	context: reading.context,
	client: reading.client,
});
const openedOf = (reading: Reading) =>
	reading.opening && "opened" in reading.opening ? reading.opening.opened : undefined;

/** A string field of a value read as an object, none otherwise. */
const fieldOf = (value: unknown, name: string): string | undefined => {
	const field = (value as Record<string, unknown> | null)?.[name];
	return typeof field === "string" ? field : undefined;
};

/** The changes another writer's body carries: a denial's registration. */
function bodyChanges(kind: string, body: unknown): Changes {
	const registration = fieldOf(body, "registration");
	return kind === "denial" && registration !== undefined ? { revoke: registration } : {};
}

/** Outcome(r) (§6.2): whether the record took, given its verdict. */
export function outcomeOf(reading: Reading, verdict: Verdict): StageOutcome {
	if (!acceptable(verdict)) return "didNotTake";
	if (reading.record.writer.role !== "core") return "took";
	const ask = askOf(reading, openedOf(reading));
	return timely(ask, reading.record.acceptedAt) ? "took" : "didNotTake";
}

type Found = {
	readonly row: Row;
	readonly verdict: Verdict;
	readonly counted?: boolean;
	readonly reason?: string;
};
const forged = (row: Row, reason?: string): Found =>
	reason === undefined ? { row, verdict: "forged" } : { row, verdict: "forged", reason };
const heldAt = (row: Row, counted = false): Found => ({ row, verdict: "held", counted });

type Bounds = { readonly lower: boolean; readonly upper: boolean };
/** VersionOK's two sides for each version the record names: below b(v) − ε, at or past b(v+1) + P + ε. */
function versionBounds(reading: Reading): Bounds | "wait" {
	const { record, versions } = reading;
	const { epsilon, propagation } = reading.context.limits;
	const named = [
		[record.registryVersion, versions?.registry],
		[record.configVersion, versions?.config],
	] as const;
	let bounds = { lower: false, upper: false };
	for (const [version, window] of named) {
		if (version === undefined) continue;
		if (!window) return "wait";
		const a = record.acceptedAt;
		bounds = {
			lower: bounds.lower || a < window.at - epsilon,
			upper:
				bounds.upper || (window.next !== undefined && a >= window.next + propagation + epsilon),
		};
	}
	return bounds;
}

/** The rows from J2 on, in the table's order, for a Core writer's record (J1 and WaitVer aside). */
function coreRows(reading: Reading, bounds: Bounds): Found {
	const { record, opening, prior } = reading;
	if (!opening || !reading.keySets)
		throw new TypeError("a Core writer's record is read with its opening and key sets");
	if (!isCoreKind(record.kind)) return forged("J2", "a Core writer names a kind it does not write");
	const opened = openedOf(reading);
	const read = opened === undefined ? undefined : readPreimage(record.kind, opened);
	if (read && !("error" in read) && record.kind === "start") {
		const parent = read.preimage.parent;
		const content = read.content as { via: string };
		if (content.via === "code" && codeStartedBefore(prior, parent))
			return forged("J2", "an approval's code is exchanged once");
	}
	const sealed = (record.sealedTo ?? []).map((s) => s.key);
	if (sealed.some((key) => !reading.keySets?.ever.includes(key)))
		return forged("J3", "sealed to a key never in a key set");
	if ("undecryptable" in opening) return forged("J4", "the preimage does not decrypt or verify");
	if (read && "error" in read && read.error === "preimage")
		return forged("J4", "the preimage is not the wire's form");
	if ("missing" in opening) return heldAt("J5");
	if ("failing" in opening) return heldAt("J6");
	const refusal = refusalOf(askOf(reading, opened));
	if (refusal !== undefined) return forged("J7", refusal);
	if (bounds.lower) return forged("J8", "accepted before its version's lower bound");
	const inherited = prior.some(
		(e) =>
			e.envelope.op === record.op &&
			e.envelope.stage < record.stage &&
			e.judgment.verdict === "held",
	);
	if (inherited) return heldAt("J9");
	// A client's record whose check the caller did not give: J7 needs what it lacks, so held.
	const unchecked = uncheckedOf(askOf(reading, opened));
	if (unchecked !== undefined) return { row: "J9", verdict: "held", reason: unchecked };
	if (bounds.upper) return heldAt("J10", true);
	if (!sealed.some((key) => reading.keySets?.atRecord.includes(key))) return heldAt("J11");
	const root = rootOf(askOf(reading, opened));
	if (root && "first" in root) return { row: "J12", verdict: "unsupported" };
	if (root !== undefined) {
		const confirmed = prior.some(
			(e) =>
				e.envelope.kind === "confirmation" &&
				e.judgment.verdict === "verified" &&
				e.parent === root.root,
		);
		if (!confirmed) return { row: "J12", verdict: "unsupported" };
	}
	return { row: "J13", verdict: "verified" };
}

/**
 * Verdict(r) (kernel-spec §6.1): a record's verdict by the first row of the judgment table it meets,
 * its outcome, and the entry its flow's later records and the fold read; or a wait (J1, WaitVer).
 */
export function judge(reading: Reading): Ruling {
	const { record } = reading;
	const envelope = {
		id: record.id,
		kind: record.kind,
		op: record.op,
		stage: record.stage,
		last: record.last,
		position: record.position,
		acceptedAt: record.acceptedAt,
	};
	let found: Found;
	let changes: Changes = {};
	let parent: string | undefined;
	let via: "code" | "refresh" | "client" | undefined;
	let client: FlowEntry["client"];
	let reset: ResetFinding | undefined;
	const role = record.writer.role;
	if (role !== "core") {
		const kinds: readonly string[] = recordKinds[role];
		if (!kinds.includes(record.kind)) {
			found = forged("J2", "the writer's role does not write the record's kind");
		} else if (record.kind === "resetBoundary") {
			// J0r: the reset rule finds it, an op not its instruction's among its faults. A body that
			// reads must still name its envelope's flow, op and previous position, as signedRecord holds
			// every other's: one that does not is the caller's to drop.
			const bound = schemas.bodies.resetBoundary.safeParse(reading.body);
			if (bound.success) {
				const { flow, op, prev } = bound.data;
				if (
					flow.of !== record.flow.of ||
					flow.id !== record.flow.id ||
					op !== record.op ||
					prev !== record.position - 1
				)
					throw new TypeError(
						"a reset boundary's body names another flow, op or position than its envelope",
					);
			}
			reset = resetFinding(
				reading.body,
				reading.state,
				reading.checks,
				reading.context,
				record.acceptedAt,
			);
			found =
				reset.verdict === "held"
					? heldAt("J0r")
					: reset.reason === undefined
						? { row: "J0r", verdict: reset.verdict }
						: { row: "J0r", verdict: reset.verdict, reason: reset.reason };
		} else {
			// J0 takes another writer's record as its signature verified, its body its kind's; what does
			// not verify is not there, so it is the caller's to drop before it is judged.
			if (!schemas.signedRecord.safeParse({ record, body: reading.body }).success)
				throw new TypeError("another writer's record is judged with its verified body, its kind's");
			parent = fieldOf(reading.body, "registration");
			changes = bodyChanges(record.kind, reading.body);
			found = { row: "J0", verdict: "verified" };
		}
	} else {
		const opening = reading.opening;
		if (opening && "failing" in opening) {
			const { since, now } = opening.failing;
			if (now - since < reading.context.limits.retry) return { wait: "temporary" };
		}
		const bounds = versionBounds(reading);
		if (bounds === "wait") return { wait: "version" };
		found = coreRows(reading, bounds);
		const opened = openedOf(reading);
		if (opened !== undefined) {
			changes = effectOf(askOf(reading, opened));
			parent = fieldOf(opened, "parent");
			if (record.kind === "start" || record.kind === "bundle") {
				const read = readPreimage(record.kind, opened);
				via = "error" in read ? undefined : read.content.via;
			}
		}
		if (record.kind === "start") client = clientOf(askOf(reading, opened));
	}
	const judgment = {
		verdict: found.verdict,
		outcome: reset ? reset.outcome : outcomeOf(reading, found.verdict),
	};
	const entry: FlowEntry = {
		envelope,
		changes,
		judgment,
		parent,
		...(via ? { via } : {}),
		...(client ? { client } : {}),
	};
	const ruling = { entry, row: found.row, counted: found.counted ?? false };
	return found.reason === undefined ? ruling : { ...ruling, reason: found.reason };
}
