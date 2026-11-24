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
	return { app, s, stores, closed, login };
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

it("keeps a pushed-out session awaiting, with its end, when the closings refuse it, and closes it at the next push-out", async () => {
	const booted = await boot();
	const { s, stores, closed, login } = booted;
	const first = await login();
	const [second] = await pushOutRefused(booted);
	expect(await stores.awaiting("alice")).toEqual([first]);
	// The refused login's session was taken off, so the listing is full again only one login on.
	now += 1000;
	await login();
	expect(closed).toEqual([]);
	now += 1000;
	await login();
	expect(closed).toEqual(["alice", "alice"]);
	expect(await stores.awaiting("alice")).toEqual([]);
	expect((await s.entryOf(first)).kind).toBe("absent");
	expect((await s.entryOf(second as string)).kind).toBe("absent");
});

it("keeps a pushed-out session awaiting without reading its record, and hands it to the closings at the next push-out though its record cannot be read", async () => {
	const booted = await boot();
	const { stores, login } = booted;
	const first = await login();
	await stores.kept.records.change(first, (r) => ({
		value: { ...(r as object), format: 2 } as unknown as StoredSession,
	}));
	await pushOutRefused(booted);
	expect(await stores.awaiting("alice")).toEqual([first]);
	for (const _ of [1, 2]) {
		now += 1000;
		await login();
	}
	expect(await stores.awaiting("alice")).toEqual([]);
	// Its close cannot read it, so it stays among the closings, for the sweep.
	expect(stores.kept.pending()).toContain(first);
});

it("lets a revocation close a session left awaiting", async () => {
	const booted = await boot();
	const { app, s, closed, login } = booted;
	const first = await login();
	await pushOutRefused(booted);
	await app.get(subjectRevocation).revoke("alice");
	expect((await s.entryOf(first)).kind).toBe("absent");
	expect(closed).toHaveLength(listingCap);
});

it("takes the opened session off the listing when the closings refuse what it pushed out, the rest left as they were", async () => {
	const booted = await boot();
	const { stores, login } = booted;
	const first = await login();
	const handles = await pushOutRefused(booted);
	const listed = (await stores.members("alice")).map(({ member }) => member).sort();
	expect(listed).toEqual([...handles].sort());
	expect(await stores.awaiting("alice")).toEqual([first]);
});

it("leaves a pushed-out session awaiting though the opened one cannot be taken off", async () => {
	const booted = await boot();
	const { stores, login } = booted;
	const first = await login();
	stores.down.listed.failNext("remove");
	await pushOutRefused(booted);
	expect(await stores.awaiting("alice")).toEqual([first]);
});
