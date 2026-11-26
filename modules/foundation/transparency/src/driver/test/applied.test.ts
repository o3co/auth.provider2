import type { Finding } from "@mod/authority-rules";
import { isUnavailable } from "@mod/kernel";
import { beforeEach, describe, expect, it } from "vitest";
import { memoryFrames } from "../../../test/fixtures/frames.ts";
import { logBook } from "../../../test/fixtures/log.ts";
import {
	allParts,
	issue,
	keyChange,
	keyStage,
	owners,
	type Reservation,
	reservationRecord,
	seeded,
} from "../../../test/fixtures/registrations.ts";
import type { Json, OperationKind, Stage, TransparencyLog } from "../../contract.ts";
import { transparencyOver } from "../driver.ts";

const flow = { of: "subject", id: "s1" } as const;
const leaseMs = 5000;
const verified: Finding = { verdict: "verified", outcome: "took" };
const didNotTake: Finding = { verdict: "verified", outcome: "didNotTake" };
const held: Finding = { verdict: "held", outcome: "took" };
const reservation: Reservation = {
	version: "res1",
	state: "verified",
	credential: "c2",
	publicKey: "p2",
};
const stage = keyStage(flow, reservation);

function makeWorld() {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	const replica = (
		instance: string,
		kinds: readonly OperationKind[] = [issue, keyChange],
		wrap: (l: TransparencyLog) => TransparencyLog = (l) => l,
		generation = 1,
	) =>
		transparencyOver({
			frames: store.frames,
			log: wrap(log.as(instance, generation)),
			kinds,
			owners,
			leaseMs,
		});
	for (const [part, value] of Object.entries(seeded))
		store.put(flow, { part, name: "state" }, value as unknown as Json);
	store.put(flow, reservationRecord, reservation as unknown as Json);
	const frame = () => store.value(flow) as { applied: number; intent: unknown } | undefined;
	return { store, log, replica, w1: replica("w1"), w2: replica("w2"), frame };
}
let world: ReturnType<typeof makeWorld>;
beforeEach(() => {
	world = makeWorld();
});

/** The key change decided and its one stage sent by w1, judged as told. */
async function placed(finding?: Finding) {
	const decided = await world.w1.decide({
		kind: "key",
		flow,
		op: "res1",
		decide: () => ({
			digest: "dk".padEnd(43, "0"),
			eff: { key: { credential: "c2", publicKey: "p2" } },
			records: [undefined],
		}),
	});
	if (!("prev" in decided)) throw new Error(decided.refused);
	const sent = await world.w1.send({ flow, op: "res1", stage, prev: decided.prev });
	if (!("answer" in sent) || sent.answer.result !== "accepted") throw new Error("not placed");
	if (finding) world.log.judge(flow, sent.answer.position, finding);
	return sent.answer;
}
const ask = { kind: "key", flow, op: "res1", stage } as const;

describe("a placed stage applied", () => {
	it("is refused unplaced where the log holds no stage of its op, appending nothing", async () => {
		expect(await world.w2.applied(ask)).toEqual({ refused: "unplaced" });
		expect(world.log.records(flow)).toHaveLength(0);
	});

	it("takes its flow in through its position as its owner, and answers how its op ended", async () => {
		const answer = await placed(verified);
		expect(await world.w1.applied(ask)).toEqual({ answer, ending: "took" });
		expect(world.frame()?.applied).toBe(1);
		// Taken in already: answered again, nothing written.
		const frame = structuredClone(world.store.value(flow));
		expect(await world.w2.applied(ask)).toEqual({ answer, ending: "took" });
		expect(world.store.value(flow)).toEqual(frame);
	});

	it("answers each ending as the step that took it in gives it", async () => {
		for (const [finding, ending] of [
			[didNotTake, "didNotTake"],
			[held, "held"],
		] as const) {
			world = makeWorld();
			const answer = await placed(finding);
			expect(await world.w1.applied(ask)).toEqual({ answer, ending });
		}
	});

	it("waits on a live owner's last stage from another replica, and is unjudged while its record is", async () => {
		await placed();
		expect(await world.w1.applied(ask)).toEqual({ refused: "unjudged" });
		world.log.judge(flow, 1, verified);
		expect(await world.w2.applied(ask)).toEqual({ refused: "waits" });
		expect(world.frame()?.applied).toBe(0);
	});

	it("never takes in past its position: a later record, judged or not, is left for its own owner", async () => {
		const answer = await placed(verified);
		// Another replica took it in first; a monitor's record after it waits.
		expect(await world.w1.step({ flow, own: "res1" })).toMatchObject({ position: 1 });
		world.log.monitor(flow, "denial", { revoke: "k1" });
		expect(await world.w2.applied(ask)).toEqual({ answer, ending: "took" });
		expect(world.frame()?.applied).toBe(1);
	});

	it("answers though a later op is open of a kind this replica has no registration of", async () => {
		const answer = await placed(verified);
		expect(await world.w1.step({ flow, own: "res1" })).toMatchObject({ position: 1 });
		const decided = await world.w1.decide({
			kind: issue.name,
			flow,
			op: "b1",
			decide: () => ({ digest: "d".repeat(43), eff: {}, records: [] }),
		});
		expect(decided).toMatchObject({ prev: 1 });
		const keysAlone = world.replica("w3", [keyChange]);
		expect(await keysAlone.applied(ask)).toEqual({ answer, ending: "took" });
	});

	it("is the caller's TypeError for a bundle's kind, an abandonment, another op's stage or another kind than its intent's", async () => {
		await placed();
		await expect(world.w1.applied({ ...ask, kind: issue.name })).rejects.toThrow(TypeError);
		await expect(
			world.w1.applied({ ...ask, stage: { ...stage, kind: "abandonment" } as Stage }),
		).rejects.toThrow(TypeError);
		await expect(world.w1.applied({ ...ask, op: "other" })).rejects.toThrow(TypeError);
		await expect(world.w1.applied({ ...ask, kind: "nothing" })).rejects.toThrow(TypeError);
	});

	it("answers a client's flow notSubject", async () => {
		const client = { of: "client", id: "c1" } as const;
		expect(
			await world.w1.applied({ ...ask, flow: client, stage: { ...stage, flow: client } }),
		).toEqual({ refused: "notSubject" });
	});

	it("stops at its position where another replica takes it in between its read and its write, a judged record after it left", async () => {
		const answer = await placed(verified);
		world.log.monitor(flow, "denial", { revoke: "k1" });
		let raced = false;
		const racing = world.replica("w1", undefined, (l) => ({
			writer: l.writer,
			digest: (preimage) => l.digest(preimage),
			append: (s2, prev) => l.append(s2, prev),
			head: (f) => l.head(f),
			of: (f, op) => l.of(f, op),
			reset: (instruction) => l.reset(instruction),
			at: async (f, position) => {
				// Read after the snapshot, before the write: another replica takes the same record in first.
				if (position === 1 && !raced) {
					raced = true;
					await world.replica("w1").step({ flow, own: "res1" });
				}
				return l.at(f, position);
			},
		}));
		expect(await racing.applied(ask)).toEqual({ answer, ending: "took" });
		expect(raced).toBe(true);
		expect(world.frame()?.applied).toBe(1);
	});

	it("is the caller's TypeError where its op's open intent is of another registered kind", async () => {
		await placed();
		const key2 = { ...keyChange, name: "key2" };
		const both = world.replica("w1", [issue, keyChange, key2]);
		await expect(both.applied({ ...ask, kind: "key2" })).rejects.toThrow(TypeError);
	});

	it("is sealed on a frame of another Core generation", async () => {
		await placed(verified);
		const later = world.replica("w1", undefined, undefined, 2);
		expect(await later.applied(ask)).toEqual({ refused: "sealed" });
	});

	it("answers a stage not its op's last with no ending", async () => {
		const decided = await world.w1.decide({
			kind: "key",
			flow,
			op: "res1",
			decide: () => ({ digest: "dk".padEnd(43, "0"), eff: {}, records: [undefined] }),
		});
		if (!("prev" in decided)) throw new Error(decided.refused);
		const first = { ...stage, last: false };
		const sent = await world.w1.send({ flow, op: "res1", stage: first, prev: decided.prev });
		if (!("answer" in sent)) throw new Error(sent.refused);
		world.log.judge(flow, 1, verified);
		expect(await world.w1.applied({ ...ask, stage: first })).toEqual({ answer: sent.answer });
	});

	it("takes in up to 64 records in one call, and answers far where more lie before its position", async () => {
		for (const count of [64, 65]) {
			world = makeWorld();
			const decided = await world.w1.decide({
				kind: "key",
				flow,
				op: "res1",
				decide: () => ({ digest: "dk".padEnd(43, "0"), eff: {}, records: [undefined] }),
			});
			if (!("prev" in decided)) throw new Error(decided.refused);
			let last: Stage = stage;
			for (let n = 1; n <= count; n++) {
				last = { ...stage, stage: n, last: n === count };
				await world.w1.send({ flow, op: "res1", stage: last, prev: n - 1 });
				world.log.judge(flow, n, verified);
			}
			const got = await world.w1.applied({ ...ask, stage: last });
			if (count === 64) expect(got).toMatchObject({ ending: "took" });
			else expect(got).toEqual({ refused: "far" });
			expect(world.frame()?.applied).toBe(64);
		}
	});

	it("returns an answer the log does not accept as it is, applying nothing", async () => {
		await placed(verified);
		const other = { ...stage, preimage: { ...stage.preimage, content: { variant: "other" } } };
		const got = await world.w1.applied({ ...ask, stage: other });
		expect(got).toMatchObject({ answer: { result: "refused", refusal: "sameIdOther" } });
		expect(world.frame()?.applied).toBe(0);
	});

	it("is unjudged where the log's at shows not yet what its append answered", async () => {
		await placed(verified);
		const lagging = world.replica("w1", undefined, (l) => ({
			writer: l.writer,
			digest: (preimage) => l.digest(preimage),
			append: (s2, prev) => l.append(s2, prev),
			head: (f) => l.head(f),
			of: (f, op) => l.of(f, op),
			reset: (instruction) => l.reset(instruction),
			at: async () => undefined,
		}));
		expect(await lagging.applied(ask)).toEqual({ refused: "unjudged" });
	});

	it("answers unavailable where the record at its position is of another id, op or flow", async () => {
		await placed(verified);
		expect(await world.w1.step({ flow, own: "res1" })).toMatchObject({ position: 1 });
		for (const change of [
			{ id: "r99" },
			{ op: "another" },
			{ flow: { of: "subject", id: "s2" } },
		]) {
			const other = world.replica("w2", undefined, (l) => ({
				writer: l.writer,
				digest: (preimage) => l.digest(preimage),
				append: (s2, prev) => l.append(s2, prev),
				head: (f) => l.head(f),
				of: (f, op) => l.of(f, op),
				reset: (instruction) => l.reset(instruction),
				at: async (f, position) => {
					const p2 = await l.at(f, position);
					return p2 && ({ ...p2, record: { ...p2.record, ...change } } as never);
				},
			}));
			await expect(other.applied(ask), JSON.stringify(change)).rejects.toSatisfy(isUnavailable);
		}
	});

	it("answers a noEffect last stage didNotTake, however it was judged", async () => {
		const decided = await world.w1.decide({
			kind: "key",
			flow,
			op: "res1",
			decide: () => ({ digest: "dk".padEnd(43, "0"), eff: {}, records: [undefined] }),
		});
		if (!("prev" in decided)) throw new Error(decided.refused);
		const none = { ...stage, kind: "noEffect" } as Stage;
		const sent = await world.w1.send({ flow, op: "res1", stage: none, prev: decided.prev });
		if (!("answer" in sent)) throw new Error(sent.refused);
		world.log.judge(flow, 1, verified);
		expect(await world.w1.applied({ ...ask, stage: none })).toEqual({
			answer: sent.answer,
			ending: "didNotTake",
		});
	});
});
