import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { closingParticipants, type LoginFacts, sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import { memoryStores } from "../../../../test/stores.ts";
import sessionLifecycle from "../../../module.ts";
import type { StoredSession } from "../../../store.ts";
import { sessionLifecycleConfig } from "../../../testing.ts";

let now = 1_800_000_000_000;
const listingCap = 20;
const facts = (): LoginFacts => ({
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: now,
	provenSince: now,
	endsAt: now + 3_600_000,
});

async function boot(log = recordingLog()) {
	const stores = memoryStores();
	const closed: string[] = [];
	const closer = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(closingParticipants).by(() => ({
			closing: async (session) => {
				closed.push(session.context.subject);
				return [];
			},
		})),
	]);
	const app = await assemble({
		modules: [sessionLifecycle, subjectRevocationStandIn, stores.module, closer],
		config: {
			...kernelConfig(),
			...sessionLifecycleConfig({ "sessions-per-subject": listingCap }),
		},
		runtime: quietRuntime({ clock: { now: () => now }, log: log.log }),
	});
	await app.start();
	const s = app.get(sessions);
	const login = async (given: Partial<LoginFacts> = {}) =>
		openedOf(await s.open({ ...facts(), ...given })).session.id;
	const logged = (event: string) => log.lines().filter((line) => line.event === event);
	/** The time a listed handle has left, if listed. */
	const leftOf = async (handle: string) =>
		(await stores.members("alice")).find(({ member }) => member === handle)?.remainingMs;
	return { app, s, stores, closed, login, logged, leftOf };
}

/** Fills alice's listing behind its first session, then fails the login that pushes it out, as the closings refuse. */
async function pushOutRefused({ s, stores, login }: Awaited<ReturnType<typeof boot>>) {
	const handles: string[] = [];
	for (let n = 0; n < listingCap - 1; n++) {
		now += 1000;
		handles.push(await login());
	}
	stores.down.closing.failNext("add");
	await expect(s.open(facts())).rejects.toSatisfy(isUnavailable);
	return handles;
}

it("puts a pushed-out session back for what it has left until the end its login gave, so the next login pushes out that one again", async () => {
	const booted = await boot();
	const { s, closed, login, leftOf } = booted;
	const endsAt = now + 1_800_000;
	const first = await login({ endsAt });
	const [second] = await pushOutRefused(booted);
	expect(await leftOf(first)).toBe(endsAt - now);
	now += 1000;
	await login();
	expect(closed).toEqual(["alice"]);
	expect((await s.entryOf(first)).kind).toBe("absent");
	expect((await s.entryOf(second as string)).kind).toBe("entered");
});

it("lists a put-back session again, so revoking the subject closes it too", async () => {
	const booted = await boot();
	const { app, s, closed, login, leftOf } = booted;
	const first = await login();
	await pushOutRefused(booted);
	expect(await leftOf(first)).toBeGreaterThan(0);
	await app.get(subjectRevocation).revoke("alice");
	expect((await s.entryOf(first)).kind).toBe("absent");
	expect(closed).toHaveLength(listingCap);
});

it("puts back no pushed-out session whose record it cannot read, counting it as neither put back nor ended", async () => {
	const booted = await boot();
	const { stores, login, leftOf, logged } = booted;
	const first = await login();
	await stores.kept.records.change(first, (r) => ({
		value: { ...(r as object), format: 2 } as unknown as StoredSession,
	}));
	await pushOutRefused(booted);
	expect(await leftOf(first)).toBeUndefined();
	expect(logged("session-lifecycle.listing_put_back_failed")).toEqual([
		expect.objectContaining({ fields: { count: 1 } }),
	]);
});

it("does not put back a pushed-out session already closed", async () => {
	const booted = await boot();
	const { s, stores, login, leftOf } = booted;
	const first = await login();
	stores.down.listed.failNext("remove");
	expect((await s.close(first)).kind).toBe("closed");
	await pushOutRefused(booted);
	expect(await leftOf(first)).toBeUndefined();
});

it("ends a pushed-out session it cannot put back, so none stays open and unlisted", async () => {
	const booted = await boot();
	const { s, stores, login, leftOf } = booted;
	const first = await login();
	stores.down.sessions.failNext("read");
	await pushOutRefused(booted);
	expect(await leftOf(first)).toBeUndefined();
	expect((await s.entryOf(first)).kind).toBe("absent");
});

it("puts a pushed-out session back though the opened one cannot be taken off", async () => {
	const booted = await boot();
	const { stores, login, leftOf } = booted;
	const first = await login();
	stores.down.listed.failNext("remove");
	await pushOutRefused(booted);
	expect(await leftOf(first)).toBeDefined();
});

it("ends a session the put-back pushes out, so none is left open off the listing, and logs how many it ended", async () => {
	const { s, stores, login, logged, leftOf } = await boot();
	const first = await login();
	const handles: string[] = [];
	for (let n = 0; n < listingCap - 1; n++) {
		now += 1000;
		handles.push(await login());
	}
	// The opened session stays listed, so the listing is full again when the first is put back.
	stores.down.closing.failNext("add");
	stores.down.listed.failNext("remove");
	await expect(s.open(facts())).rejects.toSatisfy(isUnavailable);
	expect(await leftOf(first)).toBeDefined();
	// The second login's session, the one ending first after the first's, was pushed out and ended.
	expect((await s.entryOf(handles[0] as string)).kind).toBe("absent");
	expect((await s.entryOf(handles[1] as string)).kind).toBe("entered");
	expect(logged("session-lifecycle.listing_ended")).toEqual([
		expect.objectContaining({ fields: { count: 1 } }),
	]);
});
