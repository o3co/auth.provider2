import { type Clock, type Log, type Random, Unavailable } from "@mod/kernel";
import {
	type AuthContext,
	type ClosingParticipants,
	type Entry,
	type LoginFacts,
	type Opened,
	type Session,
	type Sessions,
	sessionRules,
} from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { AttributesKeeping } from "../attributes.ts";
import type {
	ChangedSession,
	ClosingList,
	SessionStore,
	StoredSession,
	SubjectSessions,
} from "../store.ts";
import { listingOver } from "./listing/listing.ts";
import { closedFrom, fromStored, lengthOf, type SessionRecord, toStored } from "./record.ts";
import { retryingWith } from "./retrying.ts";

export interface LifecycleParts {
	readonly kept: SessionStore;
	readonly closings: ClosingList;
	readonly listed: SubjectSessions;
	readonly revocation: SubjectRevocation;
	readonly closing: ClosingParticipants;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly sweepMs: number;
	readonly attributes: AttributesKeeping;
}

export interface Lifecycle extends Sessions {
	sweep(stopping: AbortSignal): Promise<void>;
}

type OpenRecord = Extract<SessionRecord, { state: "open" }>;

/** A session's handle: 32 random bytes in base64url, 43 characters. */
const freshHandle = (random: Random) => Buffer.from(random.bytes(32)).toString("base64url");

export function lifecycleOver(parts: LifecycleParts): Lifecycle {
	const { kept, closings, listed, revocation, clock, log, sweepMs } = parts;
	const { putOffUnread, putOff, dueOf, keepOnly } = retryingWith({ kept, clock, log, sweepMs });
	const listing = listingOver({ listed, closings, log, close: (handle) => close(handle) });
	const contextOf = (record: AuthContext): AuthContext => {
		const attributes = parts.attributes.read(record.attributes);
		return Object.freeze({
			subject: record.subject,
			amr: Object.freeze([...record.amr]),
			authenticatedAt: record.authenticatedAt,
			...(record.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
			...(attributes === undefined ? {} : { attributes }),
		});
	};
	const sessionOf = (handle: string, record: AuthContext): Session =>
		Object.freeze({ id: handle, context: contextOf(record) });
	/** Closed, keeping only its subject and times, for its own length from now. */
	const closedOf = (was: SessionRecord): ChangedSession => ({
		value: toStored(closedFrom(was)),
		lifetimeMs: lengthOf(was),
	});
	/** Goes on only when the place answered created; anything else, `erased` included, is unavailable, never tried again. */
	const created = async (saving: Promise<"created" | "exists" | "erased">) => {
		if ((await saving) !== "created") throw new Unavailable("session");
	};
	/**
	 * Moves forward to `target`, never back, always writing to confirm it; none, writing nothing, where
	 * the update answers nothing. Answers the record after.
	 */
	const advance = async (handle: string, target: "closing" | "closed") => {
		const at = clock.now();
		const step = (stored: StoredSession): ChangedSession | undefined => {
			const was = fromStored(stored);
			if (!was) return undefined;
			if (was.state === "closed" || target === "closed") return closedOf(was);
			// A closing is kept until it is closed, so its participants are never skipped, even for a
			// session past its end: its tokens may still live.
			const closing = { ...was, state: "closing" as const, closingSince: was.closingSince ?? at };
			return { value: toStored(closing), lifetimeMs: "endless" };
		};
		const written = await kept.update(handle, step);
		if (!written) return undefined;
		// A record this cannot read is left as it is, and its close cannot go on.
		const after = fromStored(written.after);
		if (!after || !fromStored(written.before)) {
			putOffUnread(handle);
			throw new Unavailable("session");
		}
		return after;
	};
	const close: Sessions["close"] = async (handle) => {
		// Added to the closings first, so a closing that stops halfway is found and finished.
		await closings.add(handle);
		const record = await advance(handle, "closing");
		// Ended, never opened, or its subject erased: a handle is never reissued, so nothing to guard.
		if (!record) {
			await closings.done(handle);
			return { kind: "closed" };
		}
		if (record.state === "closing") {
			const failed = await parts.closing.closing(sessionOf(handle, record));
			for (const failure of failed) log.warn("session-lifecycle.participant_failed", failure);
			if (failed.length > 0) {
				await putOff(handle, record);
				return { kind: "pending" };
			}
			await advance(handle, "closed");
		}
		await listing.unlist(record.subject, handle);
		await closings.done(handle);
		return { kind: "closed" };
	};
	/** Goes on with every pending closing that is due; one that fails does not hold up the rest. */
	const sweep = async (stopping: AbortSignal) => {
		await listing.retryAwaiting(stopping);
		const seen = new Set<string>();
		const { failed } = await closings.each(async (handle) => {
			if (stopping.aborted) return;
			seen.add(handle);
			if (dueOf(handle, fromStored(await kept.read(handle))) <= clock.now()) await close(handle);
		});
		if (!stopping.aborted) keepOnly(seen);
		if (failed > 0) log.warn("session-lifecycle.sweep_failed", { count: failed });
	};
	/** The record, while it is open, before its end, after the subject's revocation boundary, and not pushed out. */
	const liveAt = async (handle: string): Promise<OpenRecord | undefined> => {
		const found = fromStored(await kept.read(handle));
		if (found?.state !== "open" || found.endsAt <= clock.now()) return undefined;
		const revoked = (await revocation.check(found.subject, found.openedAt)) === "revoked";
		if (revoked || (await listing.awaits(found.subject, handle))) return undefined;
		return found;
	};
	const entryOf = async (handle: string): Promise<Entry> => {
		const found = await liveAt(handle);
		if (!found) return { kind: "absent" };
		return { kind: "entered", session: sessionOf(handle, found), endsAt: found.endsAt };
	};
	/** None where no record is; a record it cannot read is Unavailable. */
	const subjectOf = async (handle: string) => {
		const stored = await kept.read(handle);
		if (stored === undefined) return undefined;
		const record = fromStored(stored);
		if (!record) throw new Unavailable("session");
		return record.subject;
	};
	const open = async (facts: LoginFacts): Promise<Opened> => {
		sessionRules.checkAuthenticatedAt(facts);
		sessionRules.checkProvenSince(facts);
		sessionRules.checkEndsAt(facts);
		// A new session every time, under a new handle: a login never carries on an earlier one.
		const handle = freshHandle(parts.random);
		const openedAt = clock.now();
		const attributes = parts.attributes.atLogin(facts.attributes, log);
		const context = {
			subject: facts.subject,
			amr: [...facts.amr],
			...sessionRules.authenticatedAtOf(facts, openedAt, () =>
				log.warn("session-lifecycle.authentication_time_capped"),
			),
			...(attributes === undefined ? {} : { attributes }),
		};
		const { endsAt } = facts;
		const record: SessionRecord = { format: 1, state: "open", ...context, openedAt, endsAt };
		await created(kept.save(handle, toStored(record), lengthOf(record), facts.subject));
		// Once saved: a boundary landing after this read is later than the opening, which entry compares.
		if ((await revocation.check(facts.subject, facts.provenSince)) === "revoked") {
			await close(handle);
			return { kind: "revoked" };
		}
		// Listed before its handle is handed out, so a revocation finds every session anyone can enter,
		// for what it has left now; one already past its end lets nobody in, so it takes no place.
		const leftMs = endsAt - clock.now();
		if (leftMs > 0) {
			const listedAs = await listed.add(facts.subject, handle, leftMs);
			if (typeof listedAs === "string") throw new Unavailable("session");
			const { pushedOut } = listedAs;
			if (pushedOut.length > 0) await listing.closePushedOut(facts.subject, handle, pushedOut);
		}
		return { kind: "opened", session: sessionOf(handle, context), endsAt };
	};
	return { open, close, entryOf, subjectOf, sweep };
}
