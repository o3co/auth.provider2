import { type Eraser, erasers } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import sessionLifecycle from "@mod/session-lifecycle/module";
import { sessionLifecycleConfig } from "@mod/session-lifecycle/testing";
import { participants } from "@mod/session-participants";
import sessionParticipants from "@mod/session-participants/module";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
const collected = contract<readonly Eraser[]>("test.erasers");

async function boot(phase: "reader" | "indexed" = "reader") {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	const closer = { failing: false, calls: 0 };
	const participant = defineModule({ name: "closer", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(participants).by(() => ({
			name: "closer",
			closing: async () => {
				closer.calls++;
				if (closer.failing) throw new Error("not yet");
			},
		})),
	]);
	const app = await assemble({
		modules: [
			sessionLifecycle,
			sessionParticipants,
			wiring,
			subjectRevocationStandIn,
			simulated.module,
			participant,
			defineModule({ name: "eraser-reader", replicaSafe: false, takes: [erasers] }, (m) => [
				m.provide(collected).by(async (c) => c.collect(erasers)),
			]),
		],
		config: { ...kernelConfig(), ...sessionLifecycleConfig() },
		runtime,
	});
	const s = app.get(sessions);
	/** A login's session handle, ending a minute on. */
	const login = async () => {
		const at = runtime.clock.now();
		const facts = { subject: "alice", amr: ["pwd"], authenticatedAt: at, provenSince: at };
		return openedOf(await s.open({ ...facts, endsAt: at + 60_000 })).session.id;
	};
	const eraser = () => app.get(collected).find((e) => e.name === "session-lifecycle") as Eraser;
	return { s, simulated, closer, login, eraser };
}

it("keeps a closed session closed through a lost answer and a failover, and fails closed when the store cannot tell", async () => {
	const { s, simulated, login } = await boot();
	const handle = await login();
	// A raw record's change is a batch on its own partition.
	let lost = false;
	simulated.beforeNext("batch", "session-store.sessions", async () => {
		lost = true;
		simulated.loseNextReply();
	});
	expect((await s.close(handle)).kind).toBe("closed");
	expect(lost).toBe(true);
	await simulated.failover();
	expect((await s.entryOf(handle)).kind).toBe("absent");
	simulated.unreachable(true);
	await expect(s.entryOf(handle)).rejects.toThrow();
});

it("keeps a closing until its participants are done, however far the store clock runs", async () => {
	const { s, simulated, closer, login } = await boot();
	const handle = await login();
	closer.failing = true;
	expect((await s.close(handle)).kind).toBe("pending");
	simulated.shiftClock(10 * 365 * 86_400_000);
	closer.failing = false;
	const calls = closer.calls;
	expect((await s.close(handle)).kind).toBe("closed");
	expect(closer.calls).toBe(calls + 1);
});

it("erases an indexed subject's sessions and listing end to end, counting the open session removed as a logout gap", async () => {
	const { s, closer, login, eraser } = await boot("indexed");
	const [open, closed] = [await login(), await login()];
	expect((await s.close(closed)).kind).toBe("closed");
	expect(eraser().erasable).toBe(true);
	const { reports, logoutGaps } = await eraser().online("alice", new AbortController().signal);
	expect(reports).toMatchObject([
		{ kind: "erased", space: "session-store.sessions", removed: 2 },
		{ kind: "erased", space: "session-store.subjects" },
	]);
	expect(logoutGaps).toBe(1);
	expect(await s.subjectOf(open)).toBeUndefined();
	// Its subject erased, a close finds no record, writes nothing and calls no participant.
	const calls = closer.calls;
	expect((await s.close(open)).kind).toBe("closed");
	expect(closer.calls).toBe(calls);
	await expect(login()).rejects.toSatisfy(isUnavailable);
});
