import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { closingParticipants, type LoginFacts, sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import { simulatedStore } from "@mod/store/testing";
import { revocations, subjectRevocation } from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import revocationStore from "@mod/subject-revocation-store/module";
import { beforeEach, describe, expect, it } from "vitest";
import sessionLifecycle from "../src/module.ts";
import type { StoredSession } from "../src/store.ts";
import { type SessionLifecycleSettings, sessionLifecycleConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

const start = 1_800_000_000_000;
const hourMs = 3_600_000;
let now = start;
beforeEach(() => {
	now = start;
});
const runtime = quietRuntime({ clock: { now: () => now } });
const facts = (subject = "alice"): LoginFacts => ({
	subject,
	amr: ["pwd"],
	authenticatedAt: now,
	provenSince: now,
	endsAt: now + hourMs,
});
/** The handles the stores list under the subject, sorted. */
const listed = async (stores: ReturnType<typeof memoryStores>, subject: string) =>
	(await stores.members(subject)).map(({ member }) => member).sort();
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** Long enough for one sweep at "sweep-interval": "1s". */
const oneSweep = () => pause(1300);
/** Long enough for a whole sweep to start and finish after the clock moves. */
const nextSweep = () => pause(2300);
const configWith = (settings: Partial<SessionLifecycleSettings> = {}) => ({
	...kernelConfig(),
	...sessionLifecycleConfig({ "sessions-per-subject": 50, ...settings }),
});
const stored = (value: object) => value as unknown as StoredSession;

interface Closer {
	failing: boolean;
	calls: number;
	done: string[];
	gate?: Promise<void> | undefined;
}

async function boot(
	settings: Partial<SessionLifecycleSettings> = {},
	extra: Module[] = [],
	parts: Partial<Runtime> = {},
) {
	const stores = memoryStores();
	const closer: Closer = { failing: false, calls: 0, done: [] };
	const participant = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(closingParticipants).by(() => ({
			closing: async (session) => {
				closer.calls++;
				const gate = closer.gate;
				if (gate) await gate;
				if (closer.failing) return [{ participant: "closer", kind: "Error" }];
				closer.done.push(session.context.subject);
				return [];
			},
		})),
	]);
	const app = await assemble({
		modules: [sessionLifecycle, subjectRevocationStandIn, stores.module, participant, ...extra],
		config: configWith(settings),
		runtime: quietRuntime({ clock: { now: () => now }, ...parts }),
	});
	await app.start();
	const s = app.get(sessions);
	/** A login's session handle. */
	const login = async (subject = "alice", given: Partial<LoginFacts> = {}) =>
		openedOf(await s.open({ ...facts(subject), ...given })).session.id;
	const listingCap = configWith(settings)["session-lifecycle"]["sessions-per-subject"] as number;
	return { app, s, stores, closer, login, listingCap };
}

describe("session-lifecycle's boot", () => {
	it("refuses to boot on a time that names no unit", async () => {
		const refused = await boot({ "sweep-interval": 30 as unknown as string }).catch((e) => e);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
			"session-lifecycle.sweep-interval",
		]);
	});

	it("refuses to boot where nothing keeps the participants", async () => {
		const refused = await assemble({
			modules: [sessionLifecycle, subjectRevocationStandIn, memoryStores().module],
			config: configWith(),
			runtime,
		}).catch((error) => error);
		expect(refused).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
			"session.closing-participants",
		]);
	});

	it("keeps a session's record and listing until the end its login gave, to the millisecond", async () => {
		const { s, stores, login } = await boot();
		const handle = await login("alice", { endsAt: now + 120_000 });
		now += 119_999;
		expect((await s.entryOf(handle)).kind).toBe("entered");
		expect(await listed(stores, "alice")).toEqual([handle]);
		now += 1;
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect(stores.kept.peek(handle)).toBeUndefined();
		expect(await listed(stores, "alice")).toEqual([]);
	});
});

describe("session attributes", () => {
	it("logs the names of the attributes a login gave that it dropped, never their values", async () => {
		const recorded = recordingLog();
		const { s } = await boot({}, [], { log: recorded.log });
		const dropped = () =>
			recorded.lines().filter((line) => line.event === "session-lifecycle.attributes_dropped");
		const login = (attributes: unknown) => s.open({ ...facts(), attributes } as LoginFacts);
		await login(undefined);
		await login({ source: "users", values: { email: "a@b.example", email_verified: true } });
		expect(dropped()).toEqual([]);
		const values = {
			email: "a@b.example",
			email_verified: "secret-flag",
			emailVerified: true,
			name: "n".repeat(513),
			role: "secret-role",
			"secret-key": 1,
			toString: "secret-text",
		};
		await login({ source: "users", values });
		await login({ source: "", values: { name: "secret-name" } });
		expect(dropped().map((line) => line.fields)).toEqual([
			{ dropped: "email_verified,name", others: 4 },
			{ dropped: "source,name", others: 0 },
		]);
		await login({
			source: "users",
			values: { email: "secret@", picture: "http://secret.example/" },
		});
		expect(dropped().at(-1)?.fields).toEqual({ dropped: "email,picture", others: 0 });
		await login({ source: "users", values: { email: "a@b.example", "secret-only": 1 } });
		expect(dropped().at(-1)?.fields).toEqual({ dropped: "", others: 1 });
		expect(JSON.stringify(recorded.lines())).not.toMatch(/secret|nnn/);
	});

	it("keeps a login's attributes under the section's caps, and a read under a cap lowered since drops a value past it", async () => {
		const values = { name: "Al", groups: Array.from({ length: 80 }, (_, n) => `g${n}`) };
		const wide = await boot({ attributes: { "groups-limit": 100 } });
		const opened = openedOf(
			await wide.s.open({ ...facts(), attributes: { source: "users", values } }),
		);
		expect(opened.session.context.attributes?.values).toEqual(values);
		const { s, stores, login } = await boot();
		const handle = await login();
		await stores.kept.records.change(handle, (r) => ({
			value: stored({ ...(r as object), attributes: { source: "users", values } }),
		}));
		const entry = await s.entryOf(handle);
		expect(entry.kind === "entered" && entry.session.context.attributes?.values).toEqual({
			name: "Al",
		});
	});

	it("rechecks a record's attributes on every read", async () => {
		const { s, stores, login } = await boot();
		const handle = await login();
		await stores.kept.records.change(handle, (r) => ({
			value: stored({
				...(r as object),
				attributes: { source: "users", values: { email: "a@b.example", name: "n".repeat(513) } },
			}),
		}));
		const entry = await s.entryOf(handle);
		const attributes = entry.kind === "entered" ? entry.session.context.attributes : undefined;
		expect(attributes).toEqual({ source: "users", values: { email: "a@b.example" } });
		expect(Object.isFrozen(attributes?.values)).toBe(true);
	});
});

describe("session authentication time", () => {
	it("keeps that a login's authentication time is unknown in the record, and nothing when it is known", async () => {
		const { stores, login } = await boot();
		const unknown = await login("alice", { authenticatedAt: "unknown" });
		const known = await login();
		expect(stores.kept.peek(unknown)).toMatchObject({
			format: 1,
			authenticatedAt: now,
			authenticatedAtUnknown: true,
		});
		expect(stores.kept.peek(known)).not.toHaveProperty("authenticatedAtUnknown");
	});

	it("keeps the opening and the end apart from an earlier authentication time", async () => {
		const { stores, login } = await boot();
		const handle = await login("alice", { authenticatedAt: now - 1_000_000 });
		expect(stores.kept.peek(handle)).toMatchObject({
			format: 1,
			openedAt: now,
			authenticatedAt: now - 1_000_000,
			endsAt: now + hourMs,
		});
	});

	it("takes a login naming its authentication time the opening as authenticated when the session opens, known, logging nothing", async () => {
		const recorded = recordingLog();
		const { s, stores } = await boot({}, [], { log: recorded.log });
		const done = openedOf(await s.open({ ...facts(), authenticatedAt: "opening" }));
		expect(done.session.context.authenticatedAt).toBe(now);
		expect(stores.kept.peek(done.session.id)).toMatchObject({
			openedAt: now,
			authenticatedAt: now,
		});
		expect(stores.kept.peek(done.session.id)).not.toHaveProperty("authenticatedAtUnknown");
		expect(
			recorded.lines().filter((l) => l.event.startsWith("session-lifecycle.authentication")),
		).toEqual([]);
		await expect(s.open({ ...facts(), authenticatedAt: "now" as never })).rejects.toThrow(
			TypeError,
		);
	});

	it("refuses, before opening anything, a login whose authentication time is no time, never naming it", async () => {
		const { s, stores } = await boot();
		for (const at of [-1, Number.NaN, Number.POSITIVE_INFINITY, 8.64e15 + 1]) {
			const opened = s.open({ ...facts(), authenticatedAt: at });
			await expect(opened, String(at)).rejects.toThrow(TypeError);
			await expect(opened).rejects.not.toThrow(String(at));
		}
		expect(await listed(stores, "alice")).toEqual([]);
		for (const at of [0, 8.64e15]) {
			const done = openedOf(await s.open({ ...facts(), authenticatedAt: at }));
			expect(done.session.context.authenticatedAt, String(at)).toBe(Math.min(at, now));
		}
	});

	it("logs only that it capped an authentication time later than the opening", async () => {
		const recorded = recordingLog();
		const { s } = await boot({}, [], { log: recorded.log });
		openedOf(await s.open(facts()));
		const done = openedOf(await s.open({ ...facts(), authenticatedAt: now + 60_000 }));
		expect(done.session.context.authenticatedAt).toBe(now);
		const capped = recorded
			.lines()
			.filter((line) => line.event === "session-lifecycle.authentication_time_capped");
		expect(capped).toHaveLength(1);
		expect(JSON.stringify(capped)).not.toContain(String(now));
		expect(JSON.stringify(capped)).not.toContain("alice");
	});
});

describe("session entry", () => {
	it("tells by handle the entry a session gives its holder", async () => {
		const { s, login } = await boot();
		const handle = await login();
		expect(await s.entryOf(handle)).toMatchObject({
			kind: "entered",
			session: { context: { subject: "alice", amr: ["pwd"] } },
			endsAt: now + hourMs,
		});
		await s.close(handle);
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect((await s.entryOf("unknown")).kind).toBe("absent");
	});

	it("lets nobody in past the subject's revocation", async () => {
		const { app, s, login } = await boot();
		const a = await login("alice");
		const b = await login("bob");
		now += 60_000;
		await app.get(subjectRevocation).revoke("alice");
		now += 60_000;
		expect((await s.entryOf(a)).kind).toBe("absent");
		expect((await s.entryOf(b)).kind).toBe("entered");
		expect((await s.entryOf(await login("alice"))).kind).toBe("entered");
	});

	it("closes a session whose proof began before a boundary whose write landed near its deadline, opened after it", async () => {
		const simulated = simulatedStore();
		const closer = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(closingParticipants).by(() => ({ closing: async () => [] })),
		]);
		const app = await assemble({
			modules: [
				sessionLifecycle,
				memoryStores().module,
				revocationModule,
				revocationStore,
				simulated.module,
				closer,
			],
			config: configWith(),
			runtime,
		});
		const s = app.get(sessions);
		const provenSince = now;
		// The revocation's write lands just short of its deadline: the boundary, 10 s on.
		simulated.beforeNext("putIfAbsent", "subject-revocation-store.boundaries", async () =>
			simulated.shiftClock(9900),
		);
		await app.get(revocations).record("alice");
		// The session opens after the boundary, so its own opening is no longer before it.
		now += 15_000;
		expect(await s.open({ ...facts(), provenSince })).toEqual({ kind: "revoked" });
		// A proof begun after the boundary opens.
		const later = openedOf(await s.open(facts()));
		expect((await s.entryOf(later.session.id)).kind).toBe("entered");
	});

	it("answers unavailable, never a refusal, when the session store cannot tell", async () => {
		const { s, stores, login } = await boot();
		const handle = await login();
		for (const ask of [() => s.entryOf(handle), () => s.subjectOf(handle)]) {
			stores.down.sessions.failNext("read");
			await expect(ask()).rejects.toSatisfy(isUnavailable);
		}
		expect((await s.entryOf(handle)).kind).toBe("entered");
	});

	it("never hands out a handle that is already taken", async () => {
		// Each draw of randomness repeats one byte: the handles collide where the order says.
		const order = [1, 1, 2];
		const random = { bytes: (n: number) => new Uint8Array(n).fill(order.shift() ?? 9) };
		const { s, login } = await boot({}, [], { random });
		const first = await login();
		await expect(s.open(facts("bob"))).rejects.toSatisfy(isUnavailable);
		expect(await s.subjectOf(first)).toBe("alice");
		expect(await s.subjectOf(await login("carol"))).toBe("carol");
	});

	it("fails a login and an entry closed when subject revocation cannot tell", async () => {
		// It answers the first login's own check, and then cannot tell.
		let told = 0;
		const failing = defineModule(
			{ name: "subject-revocation", replicaSafe: true, takes: [] },
			(m) => [
				m.provide(subjectRevocation).by(() => ({
					revoke: async () => {},
					check: async () => {
						if (told++ === 0) return "valid" as const;
						throw new Error("cannot tell");
					},
				})),
			],
		);
		const closer = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(closingParticipants).by(() => ({ closing: async () => [] })),
		]);
		const other = await assemble({
			modules: [sessionLifecycle, failing, memoryStores().module, closer],
			config: configWith(),
			runtime,
		});
		const { session } = openedOf(await other.get(sessions).open(facts()));
		await expect(other.get(sessions).entryOf(session.id)).rejects.toThrow("cannot tell");
		await expect(other.get(sessions).open(facts())).rejects.toThrow("cannot tell");
	});
});

describe("session closing", () => {
	it("stays closing until every participant has finished", async () => {
		const { s, closer, login } = await boot();
		const handle = await login();
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		expect((await s.entryOf(handle)).kind).toBe("absent");
		closer.failing = false;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.done).toEqual(["alice"]);
	});

	it("lets nobody in while a close's participants are still running", async () => {
		const { s, closer, login } = await boot();
		const handle = await login();
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		const closing = s.close(handle);
		await pause(10);
		expect(closer.calls).toBe(1);
		expect((await s.entryOf(handle)).kind).toBe("absent");
		gate.resolve();
		expect((await closing).kind).toBe("closed");
	});

	it("logs a participant that fails a close by its name and the error's kind", async () => {
		const recorded = recordingLog();
		const { s, closer, login } = await boot({}, [], { log: recorded.log });
		const handle = await login();
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		const failed = recorded
			.lines()
			.filter((l) => l.event === "session-lifecycle.participant_failed");
		expect(failed.map((line) => line.fields)).toEqual([{ participant: "closer", kind: "Error" }]);
	});

	it("never moves back from closed when two closes overlap", async () => {
		const { s, closer, login } = await boot();
		const handle = await login();
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		const first = s.close(handle);
		await pause(10);
		closer.gate = undefined;
		expect((await s.close(handle)).kind).toBe("closed");
		closer.failing = true;
		gate.resolve();
		expect((await first).kind).toBe("pending");
		const calls = closer.calls;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.calls).toBe(calls);
	});

	it("keeps a pending closing past the session's end and finishes it without the user", async () => {
		const { app, s, closer, login } = await boot({ "sweep-interval": "1s" });
		const handle = await login("alice", { endsAt: now + 60_000 });
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		now += 120_000;
		closer.failing = false;
		const calls = closer.calls;
		await oneSweep();
		expect(closer.calls).toBeGreaterThan(calls);
		const after = closer.calls;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.calls).toBe(after);
		await app.stop(1000);
	});

	it("puts off only a record still closing, never one another close ended meanwhile", async () => {
		const { s, stores, closer, login } = await boot();
		const handle = await login();
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		closer.failing = true;
		const first = s.close(handle);
		await pause(10);
		const closed = stored({
			format: 1,
			state: "closed",
			subject: "alice",
			openedAt: now,
			endsAt: now + hourMs,
		});
		stores.kept.raceNextChange(() => closed);
		gate.resolve();
		expect((await first).kind).toBe("pending");
		expect(stores.kept.peek(handle)).toEqual(closed);
		closer.gate = undefined;
		expect((await s.close(handle)).kind).toBe("closed");
	});

	it("calls the participants when closing a session past its end whose record is still kept, as any close does", async () => {
		const { s, stores, closer, login } = await boot();
		const handle = await login("alice", { endsAt: now + 60_000 });
		// Kept past its end, as a store whose clock runs behind the hosts' keeps it.
		await stores.kept.records.change(handle, (r) => ({ value: r, lifetimeMs: hourMs }));
		now += 60_000;
		expect((await s.entryOf(handle)).kind).toBe("absent");
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.calls).toBe(1);
		// Closed already, or no record at all: the close calls no one again.
		expect((await s.close(handle)).kind).toBe("closed");
		expect((await s.close("x".repeat(43))).kind).toBe("closed");
		expect(closer.calls).toBe(1);
		expect(stores.kept.peek(handle)).toMatchObject({ state: "closed" });
		expect(stores.kept.pending()).toEqual([]);
	});

	it("fails a login whose save or listing its subject's erasure refused, never trying it again", async () => {
		const { s, stores } = await boot();
		stores.erased.sessions.add("erin");
		await expect(s.open(facts("erin"))).rejects.toSatisfy(isUnavailable);
		// Saved, then refused at the listing: unlisted, and no handle handed out.
		stores.erased.listed.add("finn");
		await expect(s.open(facts("finn"))).rejects.toSatisfy(isUnavailable);
		expect(await listed(stores, "finn")).toEqual([]);
	});

	it("answers closed where there is no record, writing nothing: ended, never opened, or erased", async () => {
		const { s, stores } = await boot();
		const handle = "x".repeat(43);
		expect(await s.close(handle)).toEqual({ kind: "closed" });
		expect(stores.kept.peek(handle)).toBeUndefined();
	});

	it("keeps a closed record for its length from its closing, holding only its subject and times, then lets it go", async () => {
		const { s, stores, login } = await boot();
		const opened = now;
		const handle = await login("alice", {
			endsAt: now + 60_000,
			attributes: { source: "users", values: { name: "Al" } },
		});
		now += 30_000;
		expect((await s.close(handle)).kind).toBe("closed");
		now += 59_999;
		expect(stores.kept.peek(handle)).toEqual({
			format: 1,
			state: "closed",
			subject: "alice",
			openedAt: opened,
			endsAt: opened + 60_000,
		});
		now += 1;
		expect(stores.kept.peek(handle)).toBeUndefined();
	});

	it("lets nobody into a record of a format it does not know, and does not close it", async () => {
		const { s, stores, login } = await boot();
		const handle = await login();
		await stores.kept.records.change(handle, (r) => ({
			value: stored({ ...(r as object), format: 2 }),
		}));
		expect((await s.entryOf(handle)).kind).toBe("absent");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.peek(handle)).toMatchObject({ format: 2, state: "open" });
	});

	it("lets nobody into a record of a shape it does not know", async () => {
		const { s, stores, login } = await boot();
		const odd = [
			{ extra: true },
			{ amr: "pwd" },
			{ authenticatedAt: String(now) },
			{ authenticatedAtUnknown: false },
			{ openedAt: undefined },
			{ endsAt: undefined },
			{ attributes: { source: "users", values: { role: "admin" } } },
		];
		for (const change of odd) {
			const handle = await login();
			await stores.kept.records.change(handle, (r) => ({
				value: stored({ ...(r as object), ...change }),
			}));
			expect((await s.entryOf(handle)).kind, JSON.stringify(change)).toBe("absent");
		}
		const paused = await login();
		await stores.kept.records.change(paused, (r) => ({
			value: stored({ ...(r as object), state: "paused" }),
		}));
		await expect(s.close(paused)).rejects.toSatisfy(isUnavailable);
		const handle = "m".repeat(43);
		await stores.kept.records.create(handle, stored({ format: 1, state: "closed" }), 60_000);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
	});

	it("reads the subject of a record kept past its end, ending nothing", async () => {
		const { s, stores, closer, login } = await boot();
		const handle = await login("alice", { endsAt: now + 120_000 });
		await stores.kept.records.change(handle, (r) => ({ value: r, lifetimeMs: hourMs }));
		now += 120_001;
		expect(await s.subjectOf(handle)).toBe("alice");
		// Nothing was written: the record is still open, and a close finds it so, calling the participants.
		expect(stores.kept.peek(handle)).toMatchObject({ state: "open" });
		await s.close(handle);
		expect(closer.calls).toBe(1);
	});

	it("reads a record's subject without entering it, in any state: none for no record, unavailable for one it cannot read", async () => {
		const { s, stores, closer, login } = await boot();
		const handle = await login();
		expect(await s.subjectOf(handle)).toBe("alice");
		closer.failing = true;
		await s.close(handle);
		expect(await s.subjectOf(handle)).toBe("alice");
		closer.failing = false;
		await s.close(handle);
		expect(await s.subjectOf(handle)).toBe("alice");
		expect(await s.subjectOf("none")).toBeUndefined();
		await stores.kept.records.change(handle, (r) => ({
			value: stored({ ...(r as object), format: 2 }),
		}));
		await expect(s.subjectOf(handle)).rejects.toSatisfy(isUnavailable);
	});

	it("puts off a closing whose record it cannot read, as one whose participants fail", async () => {
		const recorded = recordingLog();
		const { s, stores, login, app } = await boot({ "sweep-interval": "1s" }, [], {
			log: recorded.log,
		});
		const failures = () =>
			recorded.lines().filter((line) => line.event === "session-lifecycle.sweep_failed");
		const handle = await login();
		await stores.kept.records.change(handle, (r) => ({
			value: stored({ ...(r as object), format: 2 }),
		}));
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		await oneSweep();
		expect(failures()).toHaveLength(0);
		now += 1000;
		await nextSweep();
		expect(failures()).toHaveLength(1);
		// Put off by half its age on this host, counted from its first failure.
		now += 600_000;
		await nextSweep();
		expect(failures()).toHaveLength(2);
		now += 1000;
		await nextSweep();
		expect(failures()).toHaveLength(2);
		await app.stop(1000);
	}, 15_000);

	it("counts a closing's age afresh once a sweep finds it finished, when its record cannot be read again", async () => {
		const recorded = recordingLog();
		const { s, stores, login, app } = await boot({ "sweep-interval": "1s" }, [], {
			log: recorded.log,
		});
		const ages = () =>
			recorded
				.lines()
				.filter((line) => line.event === "session-lifecycle.closing_pending")
				.map((line) => line.fields?.ageSeconds);
		const handle = await login();
		const format = (n: number) =>
			stores.kept.records.change(handle, (r) => ({
				value: stored({ ...(r as object), format: n }),
			}));
		await format(2);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		await format(1);
		expect((await s.close(handle)).kind).toBe("closed");
		await oneSweep();
		now += 600_000;
		await format(2);
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(ages()).toEqual([0, 0]);
		await app.stop(1000);
	});

	it("finishes a close that failed midway when it is asked again", async () => {
		const { s, stores, login } = await boot();
		const handle = await login();
		stores.down.sessions.failNext("update");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		expect((await s.close(handle)).kind).toBe("closed");
		expect(stores.kept.pending()).toEqual([]);
		expect((await s.entryOf(handle)).kind).toBe("absent");
	});

	it("sweeps at once a kept closing that stopped before it had a retry time", async () => {
		const { app, s, stores, closer, login } = await boot({ "sweep-interval": "1s" });
		const handle = await login();
		stores.down.sessions.failNext("update");
		await expect(s.close(handle)).rejects.toSatisfy(isUnavailable);
		expect(stores.kept.pending()).toEqual([handle]);
		await oneSweep();
		expect(stores.kept.pending()).toEqual([]);
		expect(closer.done).toEqual(["alice"]);
		await app.stop(1000);
	});

	it("puts off a closing that keeps failing by half its age, up to an hour, and sweeps it only once due", async () => {
		const { app, s, closer, stores, login } = await boot({ "sweep-interval": "1s" });
		const handle = await login();
		const retryAt = () => (stores.kept.peek(handle) as unknown as { retryAt: number }).retryAt;
		closer.failing = true;
		const started = now;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(started + 1000);
		now += 600_000;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(now + 300_000);
		now += 7_200_000;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(retryAt()).toBe(now + 3_600_000);
		const calls = closer.calls;
		await oneSweep();
		expect(closer.calls).toBe(calls);
		now = retryAt();
		await oneSweep();
		expect(closer.calls).toBeGreaterThan(calls);
		await app.stop(1000);
	});

	it("stops sweeping when the host stops, once the closing under way is done", async () => {
		const { app, s, closer, login } = await boot({ "sweep-interval": "1s" });
		closer.failing = true;
		for (const subject of ["alice", "bob"]) {
			expect((await s.close(await login(subject))).kind).toBe("pending");
		}
		closer.failing = false;
		const gate = Promise.withResolvers<void>();
		closer.gate = gate.promise;
		now += 2000;
		await oneSweep();
		const stopping = app.stop(5000);
		closer.gate = undefined;
		gate.resolve();
		await stopping;
		expect(closer.done).toHaveLength(1);
	});

	it("goes on with the other pending closings when one fails in a sweep", async () => {
		const { app, s, stores, closer, login } = await boot({ "sweep-interval": "1s" });
		const handles = [await login("alice"), await login("bob")];
		closer.failing = true;
		for (const handle of handles) expect((await s.close(handle)).kind).toBe("pending");
		closer.failing = false;
		now += 2000;
		stores.down.sessions.failNext("read");
		await oneSweep();
		expect(closer.done).toHaveLength(1);
		now += 2000;
		await oneSweep();
		expect([...closer.done].sort()).toEqual(["alice", "bob"]);
		await app.stop(1000);
	});
});

describe("each subject's sessions", () => {
	it("lists each login's session under its subject until its end, and takes it off once closed", async () => {
		const { s, stores, login } = await boot();
		const ending = { endsAt: now + 60_000 };
		const first = await login("alice", ending);
		const second = await login("alice", ending);
		const other = await login("bob", ending);
		expect(await listed(stores, "alice")).toEqual([first, second].sort());
		expect(await listed(stores, "bob")).toEqual([other]);
		await s.close(first);
		expect(await listed(stores, "alice")).toEqual([second]);
		now += 60_000;
		expect(await listed(stores, "alice")).toEqual([]);
	});

	it("keeps a pending close listed until it is closed", async () => {
		const { s, stores, closer, login } = await boot();
		const handle = await login();
		closer.failing = true;
		expect((await s.close(handle)).kind).toBe("pending");
		expect(await listed(stores, "alice")).toEqual([handle]);
		closer.failing = false;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(await listed(stores, "alice")).toEqual([]);
	});

	it("hands out no handle when a login's write takes effect but its answer is lost, leaving a listed one listed", async () => {
		for (const write of ["sessions.save", "listed.add"] as const) {
			const random = { bytes: (n: number) => new Uint8Array(n).fill(1) };
			const { s, stores } = await boot({}, [], { random });
			const handle = Buffer.from(new Uint8Array(32).fill(1)).toString("base64url");
			stores.lost.add(write);
			await expect(s.open(facts())).rejects.toSatisfy(isUnavailable);
			expect(await listed(stores, "alice")).toEqual(write === "listed.add" ? [handle] : []);
		}
	});

	it("fails a login whose session it cannot list", async () => {
		const { s, stores } = await boot();
		stores.down.listed.failNext("add");
		await expect(s.open(facts())).rejects.toSatisfy(isUnavailable);
	});

	it("closes a session all the same when it cannot be taken off the listing, logging it by kind", async () => {
		const recorded = recordingLog();
		const { s, stores, login } = await boot({}, [], { log: recorded.log });
		const handle = await login();
		stores.down.listed.failNext("remove");
		expect((await s.close(handle)).kind).toBe("closed");
		const failed = recorded
			.lines()
			.filter((line) => line.event === "session-lifecycle.listing_failed");
		expect(failed.map((line) => line.fields)).toEqual([{ step: "remove", kind: "Unavailable" }]);
	});

	it("lists as many sessions a subject as the section says", async () => {
		const { s, closer, login } = await boot({ "sessions-per-subject": 2 });
		const first = await login();
		now += 1000;
		await login();
		now += 1000;
		await login();
		expect(closer.done).toEqual(["alice"]);
		expect((await s.entryOf(first)).kind).toBe("absent");
	});
});

describe("revoking a subject", () => {
	it("closes every listed session of the subject through close, so the participants run, and no one else's", async () => {
		const { app, s, stores, closer, login } = await boot();
		const [first, second, other] = [await login(), await login(), await login("bob")];
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toEqual(["alice", "alice"]);
		expect(await listed(stores, "alice")).toEqual([]);
		expect((await s.entryOf(first)).kind).toBe("absent");
		expect((await s.entryOf(second)).kind).toBe("absent");
		expect((await s.entryOf(other)).kind).toBe("entered");
	});

	it("leaves a close whose participants fail pending and listed, to be finished like any other", async () => {
		const { app, s, stores, closer, login } = await boot();
		const handle = await login();
		closer.failing = true;
		await app.get(subjectRevocation).revoke("alice");
		expect(await listed(stores, "alice")).toEqual([handle]);
		closer.failing = false;
		expect((await s.close(handle)).kind).toBe("closed");
		expect(closer.done).toEqual(["alice"]);
	});

	it("goes on past a close that fails, and fails the follower so the revocation logs it", async () => {
		const recorded = recordingLog();
		const { app, stores, closer, login } = await boot({}, [], { log: recorded.log });
		await login();
		await login();
		stores.down.closing.failNext("add");
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toEqual(["alice"]);
		// The listing answers in handle order, not login order, so either session may be the one left.
		expect(await listed(stores, "alice")).toHaveLength(1);
		const failed = recorded.lines().filter((l) => l.event === "subject-revocation.follower_failed");
		expect(failed.map((line) => line.fields)).toEqual([
			{ follower: "session-lifecycle", kind: "Unavailable" },
		]);
	});

	/** Logs alice in `count` times a second apart, and answers the handles. */
	const fill = async (login: () => Promise<string>, count: number) => {
		const handles: string[] = [];
		for (let n = 0; n < count; n++) {
			now += 1000;
			handles.push(await login());
		}
		return handles;
	};

	it("closes a session pushed out of a full listing through close, so the participants run, logging only the count", async () => {
		const recorded = recordingLog();
		const { s, closer, login, listingCap } = await boot({}, [], { log: recorded.log });
		const first = await login();
		await fill(login, listingCap);
		const pushed = recorded
			.lines()
			.filter((l) => l.event === "session-lifecycle.listing_pushed_out");
		expect(pushed).toEqual([
			{ level: "warn", event: "session-lifecycle.listing_pushed_out", fields: { count: 1 } },
		]);
		expect((await s.entryOf(first)).kind).toBe("absent");
		expect(closer.done).toEqual(["alice"]);
	});

	it("lets the login in when a pushed-out close cannot finish yet, and the sweep finishes it", async () => {
		const { app, s, closer, login, listingCap } = await boot({ "sweep-interval": "1s" });
		const first = await login();
		closer.failing = true;
		const [last] = (await fill(login, listingCap)).slice(-1);
		expect((await s.entryOf(last as string)).kind).toBe("entered");
		expect((await s.entryOf(first)).kind).toBe("absent");
		closer.failing = false;
		now += 2000;
		await oneSweep();
		expect(closer.done).toEqual(["alice"]);
		await app.stop(1000);
	});

	it("fails the login and keeps the pushed-out session awaiting in the listing when it cannot be kept for closing", async () => {
		const { app, s, stores, closer, login, listingCap } = await boot();
		const first = await login();
		const rest = await fill(login, listingCap - 1);
		stores.down.closing.failNext("add");
		await expect(s.open(facts())).rejects.toSatisfy(isUnavailable);
		expect(await listed(stores, "alice")).toEqual([...rest].sort());
		expect(await stores.awaiting("alice")).toEqual([first]);
		expect((await s.entryOf(first)).kind).toBe("entered");
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.done).toHaveLength(listingCap);
		expect((await s.entryOf(first)).kind).toBe("absent");
	});

	it("takes no place in a full listing for a session whose end has passed, pushing nothing out", async () => {
		const { s, stores, closer, login, listingCap } = await boot();
		const handles = await fill(login, listingCap);
		const passed = openedOf(await s.open({ ...facts(), endsAt: now }));
		expect((await s.entryOf(passed.session.id)).kind).toBe("absent");
		expect(closer.calls).toBe(0);
		expect(await listed(stores, "alice")).toEqual([...handles].sort());
	});

	it("lists a session for what it has left when it is listed, past the save and the boundary's read", async () => {
		const slow = defineModule({ name: "subject-revocation", replicaSafe: true, takes: [] }, (m) => [
			m.provide(subjectRevocation).by(() => ({
				revoke: async () => {},
				check: async () => {
					now += 10_000;
					return "valid" as const;
				},
			})),
		]);
		const stores = memoryStores();
		const closer = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(closingParticipants).by(() => ({ closing: async () => [] })),
		]);
		const app = await assemble({
			modules: [sessionLifecycle, slow, stores.module, closer],
			config: configWith(),
			runtime,
		});
		const { endsAt } = openedOf(await app.get(sessions).open({ ...facts(), endsAt: now + 60_000 }));
		expect((await stores.members("alice")).map(({ remainingMs }) => remainingMs)).toEqual([
			endsAt - now,
		]);
	});

	it("never pushes out the session being opened, even when it ends before every one listed", async () => {
		const { s, stores, closer, login, listingCap } = await boot();
		const [first, ...rest] = await fill(login, listingCap);
		const { session } = openedOf(await s.open({ ...facts(), endsAt: now + 60_000 }));
		expect((await s.entryOf(session.id)).kind).toBe("entered");
		expect(closer.done).toEqual(["alice"]);
		const after = await listed(stores, "alice");
		expect(after).toHaveLength(rest.length + 1);
		expect(after).toContain(session.id);
		expect(after).not.toContain(first);
	});

	it("refuses the subject's sessions by the boundary even when their listing cannot be read", async () => {
		const { app, s, stores, closer, login } = await boot();
		const handle = await login();
		stores.down.listed.failNext("members");
		await app.get(subjectRevocation).revoke("alice");
		expect(closer.calls).toBe(0);
		expect((await s.entryOf(handle)).kind).toBe("absent");
	});
});

it("takes every handle its takes name", async () => {
	const closer = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(closingParticipants).by(() => ({ closing: async () => [] })),
	]);
	const modules = [sessionLifecycle, subjectRevocationStandIn, memoryStores().module, closer];
	expect(
		(await takesUnused({ modules, config: configWith() }))["session-lifecycle"],
	).toBeUndefined();
});
