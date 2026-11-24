import { defineModule, isUnavailable, type Log, Unavailable } from "@mod/kernel";
import { attributeCaps, keepingWith, type SourcedAttributes } from "@mod/login-attributes";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { describe, expect, it } from "vitest";
import {
	type AuthContext,
	type CloseOutcome,
	closingParticipants,
	type Entry,
	type LoginFacts,
	type Opened,
	type Session,
	type Sessions,
	sessionRules,
	sessions,
} from "./contract.ts";

/** Keeping under login-attributes' default caps, as an app that sets none keeps a login's attributes. */
const keptByDefault = keepingWith(attributeCaps.parse({}));

/** The session and end an `open` answered, for a test that opens one: a refused one throws. */
export function openedOf(answer: Opened): { readonly session: Session; readonly endsAt: number } {
	if (answer.kind !== "opened") throw new Error(`session: the login was ${answer.kind}`);
	return { session: answer.session, endsAt: answer.endsAt };
}

export function stubSessions(parts: Partial<Sessions> = {}): Sessions {
	return {
		open: async () => {
			throw new Error("not in this test");
		},
		close: async () => ({ kind: "closed" }),
		entryOf: async () => ({ kind: "absent" }),
		subjectOf: async () => undefined,
		...parts,
	};
}

/** A composition that offers sessions, as one implementation of the contract does, with a participant in closing whose work can be made to fail. */
export interface SessionsPlace {
	readonly sessions: Sessions;
	now(): number;
	advance(ms: number): void;
	revokeSubject(subject: string): Promise<{ readonly complete: boolean }>;
	/** How many sessions a subject's listing holds before a login pushes one out. */
	readonly listingCap: number;
	/** Makes the next write to a subject's listing fail as unavailable. */
	failNextListing(): void;
	/** Subjects whose sessions the participant finished closing. */
	readonly closed: readonly string[];
	failClosing(on: boolean): void;
}

/** What every implementation of sessions must do, as a caller sees it. */
export function sessionsContract(name: string, open: () => Promise<SessionsPlace>): void {
	const hourMs = 3_600_000;
	const facts = (place: SessionsPlace, subject = "alice"): LoginFacts => ({
		subject,
		amr: ["pwd"],
		authenticatedAt: place.now(),
		provenSince: place.now(),
		endsAt: place.now() + hourMs,
	});
	describe(`sessions' contract: ${name}`, () => {
		it("opens through open, telling it opened with its end, and refuses a login stating no proof's start or end, or one of no epoch milliseconds, before anything", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			expect(done.endsAt).toBe(place.now() + hourMs);
			const { provenSince: _, ...unproven } = facts(place);
			const { endsAt: __, ...endless } = facts(place);
			for (const over of [
				unproven,
				endless,
				{ ...facts(place), provenSince: "then" },
				{ ...facts(place), endsAt: "later" },
			] as never[]) {
				await expect(place.sessions.open(over)).rejects.toThrow(TypeError);
			}
			expect(place.closed).toEqual([]);
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("entered");
		});

		it("refuses a login whose proof began at or before its subject's revocation, closing its session, and opens one whose proof began after it", async () => {
			const place = await open();
			const provenSince = place.now();
			await place.revokeSubject("carol");
			const refused = await place.sessions.open({ ...facts(place, "carol"), provenSince });
			expect(refused).toEqual({ kind: "revoked" });
			// Its record was saved, so it is closed as any session is, its participants called.
			expect(place.closed).toContain("carol");
			place.advance(60_000);
			const opened = openedOf(await place.sessions.open(facts(place, "carol")));
			expect((await place.sessions.entryOf(opened.session.id)).kind).toBe("entered");
		});

		it("opens a session under a new handle on each login, which its handle enters", async () => {
			const place = await open();
			const first = openedOf(await place.sessions.open(facts(place)));
			const second = openedOf(await place.sessions.open(facts(place)));
			expect(second.session.id).not.toBe(first.session.id);
			for (const done of [first, second]) {
				const entry = await place.sessions.entryOf(done.session.id);
				expect(entry).toMatchObject({
					kind: "entered",
					session: { id: done.session.id, context: { subject: "alice", amr: ["pwd"] } },
				});
				expect(entry.kind === "entered" && entry.session.context.authenticatedAt).toBe(place.now());
			}
			expect(await place.sessions.entryOf("x".repeat(43))).toEqual({ kind: "absent" });
		});

		it("keeps a session's subject for as long as it lives, and never names another session by its handle", async () => {
			const place = await open();
			const first = openedOf(await place.sessions.open(facts(place)));
			const second = openedOf(await place.sessions.open(facts(place, "bob")));
			expect(await place.sessions.entryOf(first.session.id)).toMatchObject({
				session: { context: { subject: "alice" } },
			});
			expect(await place.sessions.entryOf(second.session.id)).toMatchObject({
				session: { context: { subject: "bob" } },
			});
		});

		it("ends a session at the end its opening was given, and when its subject is revoked", async () => {
			const place = await open();
			const lived = openedOf(await place.sessions.open(facts(place)));
			const revoked = openedOf(await place.sessions.open(facts(place, "bob")));
			await place.revokeSubject("bob");
			expect((await place.sessions.entryOf(revoked.session.id)).kind).toBe("absent");
			place.advance(hourMs - 1);
			expect(await place.sessions.entryOf(lived.session.id)).toMatchObject({
				kind: "entered",
				endsAt: lived.endsAt,
			});
			place.advance(1);
			expect((await place.sessions.entryOf(lived.session.id)).kind).toBe("absent");
		});

		it("keeps the end it was given, however short or long, from no setting of its own", async () => {
			const place = await open();
			const short = openedOf(
				await place.sessions.open({ ...facts(place), endsAt: place.now() + 1000 }),
			);
			const long = openedOf(
				await place.sessions.open({
					...facts(place, "bob"),
					endsAt: place.now() + 90 * 86_400_000,
				}),
			);
			const passed = await place.sessions.open({ ...facts(place, "carol"), endsAt: place.now() });
			expect(passed.kind).toBe("opened");
			if (passed.kind === "opened") {
				expect((await place.sessions.entryOf(passed.session.id)).kind).toBe("absent");
			}
			place.advance(1000);
			expect((await place.sessions.entryOf(short.session.id)).kind).toBe("absent");
			place.advance(89 * 86_400_000);
			expect(await place.sessions.entryOf(long.session.id)).toMatchObject({
				kind: "entered",
				endsAt: long.endsAt,
			});
		});

		it("counts the revocation from the opening, not an earlier authentication time", async () => {
			const place = await open();
			await place.revokeSubject("alice");
			place.advance(60_000);
			const opened = place.now();
			const done = openedOf(
				await place.sessions.open({ ...facts(place), authenticatedAt: opened - 120_000 }),
			);
			expect(done.session.context.authenticatedAt).toBe(opened - 120_000);
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("entered");
		});

		it("keeps the authentication time a login reports, or that it is unknown", async () => {
			const place = await open();
			const known = openedOf(
				await place.sessions.open({ ...facts(place), authenticatedAt: place.now() - 500 }),
			);
			expect(known.session.context.authenticatedAt).toBe(place.now() - 500);
			expect(known.session.context.authenticatedAtUnknown).toBeUndefined();
			const opened = place.now();
			const unknown = openedOf(
				await place.sessions.open({ ...facts(place, "bob"), authenticatedAt: "unknown" }),
			);
			place.advance(1000);
			const entry = await place.sessions.entryOf(unknown.session.id);
			for (const context of [
				unknown.session.context,
				entry.kind === "entered" && entry.session.context,
			]) {
				expect(context).toMatchObject({ authenticatedAt: opened, authenticatedAtUnknown: true });
			}
		});

		it("takes an authentication time later than the opening as the opening, and opening as the opening, known", async () => {
			const place = await open();
			const opened = place.now();
			for (const authenticatedAt of [opened + 60_000, "opening" as const]) {
				const done = openedOf(await place.sessions.open({ ...facts(place), authenticatedAt }));
				expect(done.session.context.authenticatedAt).toBe(opened);
				expect(done.session.context.authenticatedAtUnknown).toBeUndefined();
			}
		});

		it("throws a TypeError, naming no value, for an authentication time that is no time, opening nothing", async () => {
			const place = await open();
			for (const at of [-1, Number.NaN, Number.POSITIVE_INFINITY, 8.64e15 + 1]) {
				const opened = place.sessions.open({ ...facts(place), authenticatedAt: at });
				await expect(opened, String(at)).rejects.toThrow(TypeError);
				await expect(opened).rejects.not.toThrow(String(at));
			}
			expect(place.closed).toEqual([]);
		});

		it("closes a session past its end without calling the participants", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			place.advance(hourMs);
			const closed = await place.sessions.close(done.session.id);
			// What the close found (`from`) is the implementation's: a record gone, or one it ended.
			expect(closed.kind).toBe("closed");
			expect(closed.session).toBeUndefined();
			expect(place.closed).toEqual([]);
		});

		it("hands out every session frozen", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			const entry = await place.sessions.entryOf(done.session.id);
			const given = [done.session, entry.kind === "entered" && entry.session];
			expect(given.map((session) => Object.isFrozen(session))).toEqual([true, true]);
		});

		it("closes once every participant is done, and lets nobody in meanwhile", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			place.failClosing(true);
			expect((await place.sessions.close(done.session.id)).kind).toBe("pending");
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("absent");
			place.failClosing(false);
			expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
			expect(place.closed).toEqual(["alice"]);
			expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
			expect(place.closed).toEqual(["alice"]);
		});

		it("keeps the attributes a login gives under their source, as they were at login, until it closes", async () => {
			const place = await open();
			const values = {
				email: "alice@example.com",
				email_verified: true,
				name: "Alice",
				picture: "https://pictures.example/alice",
				groups: ["staff", "ops"],
			};
			const given = { source: "users", values };
			const done = openedOf(await place.sessions.open({ ...facts(place), attributes: given }));
			values.groups.push("admin");
			values.name = "Mallory";
			const kept = {
				source: "users",
				values: { ...values, name: "Alice", groups: ["staff", "ops"] },
			};
			expect(done.session.context.attributes).toEqual(kept);
			const entry = await place.sessions.entryOf(done.session.id);
			expect(entry.kind === "entered" && entry.session.context.attributes).toEqual(kept);
			const bare = openedOf(await place.sessions.open(facts(place, "bob")));
			expect(bare.session.context).not.toHaveProperty("attributes");
		});

		it("keeps a login's attributes as login-attributes keeps them, at login and on entry alike", async () => {
			const place = await open();
			const keptOf = async (given: unknown) => {
				const attributes = given as SourcedAttributes;
				const done = openedOf(await place.sessions.open({ ...facts(place), attributes }));
				const entry = await place.sessions.entryOf(done.session.id);
				expect(entry.kind === "entered" && entry.session.context.attributes).toEqual(
					done.session.context.attributes,
				);
				return done.session.context.attributes;
			};
			const givens = [
				{ source: "users", values: { email: "a@b.example", name: "n".repeat(513), groups: [2] } },
				{ source: "users", values: { email: "a@", email_verified: true, name: "Al\u0000" } },
				{ source: "users", values: { picture: "http://p.example/a", name: "Al", role: "admin" } },
				{ source: "", values: { name: "Al" } },
				{ source: "users", values: null },
			];
			for (const given of givens) {
				expect(await keptOf(given), JSON.stringify(given)).toEqual(keptByDefault(given).kept);
			}
		});

		it("reads the subject of a session's record in any state, writing nothing, and none where no record is", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place, "bob")));
			expect(await place.sessions.subjectOf(done.session.id)).toBe("bob");
			await place.sessions.close(done.session.id);
			expect(await place.sessions.subjectOf(done.session.id)).toBe("bob");
			expect(await place.sessions.subjectOf("no-such-handle")).toBeUndefined();
			// It ends no session and calls no participant.
			const live = openedOf(await place.sessions.open(facts(place, "carol")));
			place.advance(hourMs - 1);
			const closedBefore = [...place.closed];
			expect(await place.sessions.subjectOf(live.session.id)).toBe("carol");
			expect(place.closed).toEqual(closedBefore);
			expect((await place.sessions.entryOf(live.session.id)).kind).toBe("entered");
		});

		it("closes every live session of a revoked subject, calling the participants, and no one else's", async () => {
			const place = await open();
			openedOf(await place.sessions.open(facts(place)));
			openedOf(await place.sessions.open(facts(place)));
			const other = openedOf(await place.sessions.open(facts(place, "bob")));
			await place.revokeSubject("alice");
			expect(place.closed).toEqual(["alice", "alice"]);
			expect((await place.sessions.entryOf(other.session.id)).kind).toBe("entered");
		});

		it("answers a revocation incomplete while a close it made is left pending, and complete once finished", async () => {
			const place = await open();
			openedOf(await place.sessions.open(facts(place)));
			place.failClosing(true);
			expect(await place.revokeSubject("alice")).toEqual({ complete: false });
			place.failClosing(false);
			expect(await place.revokeSubject("alice")).toEqual({ complete: true });
			expect(place.closed).toEqual(["alice"]);
		});

		it("closes the session ending first that its subject's full listing pushes out, calling the participants", async () => {
			const place = await open();
			const first = openedOf(await place.sessions.open(facts(place)));
			const others = openedOf(await place.sessions.open(facts(place, "bob")));
			for (let n = 0; n < place.listingCap; n++) {
				place.advance(1000);
				openedOf(await place.sessions.open(facts(place)));
			}
			expect(place.closed).toEqual(["alice"]);
			expect((await place.sessions.entryOf(first.session.id)).kind).toBe("absent");
			expect((await place.sessions.entryOf(others.session.id)).kind).toBe("entered");
		});

		it("fails a login whose session cannot be listed under its subject", async () => {
			const place = await open();
			place.failNextListing();
			await expect(place.sessions.open(facts(place))).rejects.toSatisfy(isUnavailable);
			const done = openedOf(await place.sessions.open(facts(place)));
			expect((await place.sessions.entryOf(done.session.id)).kind).toBe("entered");
		});

		it("names a closed session for its length from its last close", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			const named = { id: done.session.id, subject: "alice" };
			for (let n = 0; n < 3; n++) {
				expect((await place.sessions.close(done.session.id)).session).toEqual(named);
				place.advance(hourMs - 1);
			}
		});

		it("says the state each close found the record in: open, closing while left pending, then closed", async () => {
			const place = await open();
			const done = openedOf(await place.sessions.open(facts(place)));
			const from = async () => (await place.sessions.close(done.session.id)).from;
			place.failClosing(true);
			expect(await from()).toBe("open");
			expect(await from()).toBe("closing");
			place.failClosing(false);
			expect(await from()).toBe("closing");
			expect(await from()).toBe("closed");
			expect((await place.sessions.close("x".repeat(43))).from).toBeUndefined();
		});

		it("names the session a close ended or left pending, by its handle and subject", async () => {
			const place = await open();
			const named = (done: { session: Session }) => ({ id: done.session.id, subject: "alice" });
			const ended = openedOf(await place.sessions.open(facts(place)));
			expect((await place.sessions.close(ended.session.id)).session).toEqual(named(ended));
			const pending = openedOf(await place.sessions.open(facts(place)));
			place.failClosing(true);
			expect(await place.sessions.close(pending.session.id)).toMatchObject({
				kind: "pending",
				session: named(pending),
			});
			place.failClosing(false);
			expect(await place.sessions.close(pending.session.id)).toMatchObject({
				kind: "closed",
				session: named(pending),
			});
		});
	});
}

/** How many sessions the stand-in lists under a subject before a login pushes one out. */
export const standInListingCap = 100;

/** What the stand-in keeps of a login's attributes, as login-attributes keeps them, logging dropped names. */
function keptAtLogin(given: unknown, log: Log): SourcedAttributes | undefined {
	const { kept, dropped, others } = keptByDefault(given);
	if (dropped.length > 0 || others > 0) {
		log.warn("session.attributes_dropped", { dropped: dropped.join(","), others });
	}
	return kept;
}

/** Each stand-in's listing: the handles it lists under a subject, and a switch to fail its next write. */
const listingOf = new WeakMap<
	Sessions,
	{ members(subject: string): readonly string[]; failNext(): void }
>();

/** Makes the stand-in's next write to a subject's listing fail as unavailable. */
export function failStandInListing(stand: Sessions): void {
	listingOf.get(stand)?.failNext();
}

type Kept = {
	context: AuthContext;
	state: "open" | "closing" | "closed";
	openedAt: number;
	endsAt: number;
	/** When the record is gone: its end, none while closing, its length from its last close once closed. */
	until: number;
};

/**
 * A stand-in for tests of the modules that use sessions: records kept in memory on the composition's
 * clock. It compares subject revocation as the contract has it, and calls the participants when a
 * session closes, through `closingParticipants` where a module contributes them; none contributed is
 * no participant. A pending close goes on only when it is asked again: there is no sweep. It lists
 * each subject's sessions up to `standInListingCap`, and closes them through `close` when the listing
 * pushes one out or the subject is revoked.
 */
export const sessionStandIn = defineModule(
	{ name: "session", replicaSafe: false, takes: [closingParticipants, subjectRevocation] },
	(m) => [
		m.provide(sessions).by(async (c) => {
			const revocation = await c.get(subjectRevocation);
			const [closing] = await c.collect(closingParticipants);
			const kept = new Map<string, Kept>();
			/** Each subject's listing: when each listed handle ends. */
			const listing = new Map<string, Map<string, number>>();
			let failListing = false;
			const listedUnder = (subject: string) =>
				[...(listing.get(subject) ?? [])].filter(([, until]) => until > c.clock.now());
			/** Lists the session being opened, answering those pushed out over the cap: the others that end first. */
			const list = (subject: string, handle: string, until: number) => {
				if (failListing) {
					failListing = false;
					throw new Unavailable("session");
				}
				const byEnd = listedUnder(subject).sort(
					([a, aEnds], [b, bEnds]) => aEnds - bEnds || (a < b ? -1 : a > b ? 1 : 0),
				);
				const over = Math.max(0, byEnd.length + 1 - standInListingCap);
				listing.set(subject, new Map([...byEnd.slice(over), [handle, until]]));
				return byEnd.slice(0, over).map(([pushed]) => pushed);
			};
			const found = (handle: string) => {
				const record = kept.get(handle);
				return record && (record.state === "closing" || record.until > c.clock.now())
					? record
					: undefined;
			};
			const sessionOf = (handle: string, record: Kept): Session =>
				Object.freeze({ id: handle, context: record.context });
			const entryOf = async (handle: string): Promise<Entry> => {
				const record = found(handle);
				if (record?.state !== "open" || record.endsAt <= c.clock.now()) return { kind: "absent" };
				const subject = record.context.subject;
				if ((await revocation.check(subject, record.openedAt)) === "revoked") {
					return { kind: "absent" };
				}
				return { kind: "entered", session: sessionOf(handle, record), endsAt: record.endsAt };
			};
			const close = async (handle: string): Promise<CloseOutcome> => {
				const record = found(handle);
				if (!record) return { kind: "closed" };
				const session = { id: handle, subject: record.context.subject };
				const from = record.state;
				if (record.state !== "closed") {
					record.state = "closing";
					const failed = closing ? await closing.closing(sessionOf(handle, record)) : [];
					for (const failure of failed) c.log.warn("session.participant_failed", failure);
					if (failed.length > 0) return { kind: "pending", session, from };
				}
				record.state = "closed";
				record.until = c.clock.now() + Math.max(1, record.endsAt - record.openedAt);
				listing.get(record.context.subject)?.delete(handle);
				return { kind: "closed", session, from };
			};
			const open = async (facts: LoginFacts): Promise<Opened> => {
				sessionRules.checkAuthenticatedAt(facts);
				sessionRules.checkProvenSince(facts);
				sessionRules.checkEndsAt(facts);
				const handle = Buffer.from(c.random.bytes(32)).toString("base64url");
				const openedAt = c.clock.now();
				const attributes = keptAtLogin(facts.attributes, c.log);
				const context = Object.freeze({
					subject: facts.subject,
					amr: Object.freeze([...facts.amr]),
					...sessionRules.authenticatedAtOf(facts, openedAt, () =>
						c.log.warn("session.authentication_time_capped"),
					),
					...(attributes === undefined ? {} : { attributes }),
				});
				const { endsAt } = facts;
				kept.set(handle, { context, state: "open", openedAt, endsAt, until: endsAt });
				if ((await revocation.check(facts.subject, facts.provenSince)) === "revoked") {
					await close(handle);
					return { kind: "revoked" };
				}
				for (const pushed of list(facts.subject, handle, endsAt)) await close(pushed);
				return { kind: "opened", session: sessionOf(handle, kept.get(handle) as Kept), endsAt };
			};
			const stand: Sessions = {
				open,
				close,
				entryOf,
				subjectOf: async (handle) => found(handle)?.context.subject,
			};
			listingOf.set(stand, {
				members: (subject) => listedUnder(subject).map(([handle]) => handle),
				failNext: () => {
					failListing = true;
				},
			});
			return stand;
		}),
		m.contribute(revocationFollowers).by((c) => {
			const lateSessions = c.late(sessions);
			const members = async (subject: string) =>
				(listingOf.get(lateSessions())?.members(subject) ?? []).map((member) => ({ member }));
			return {
				name: "session",
				follow: (subject) =>
					sessionRules.closeListed(subject, { members }, (handle) => lateSessions().close(handle)),
			};
		}),
	],
);
