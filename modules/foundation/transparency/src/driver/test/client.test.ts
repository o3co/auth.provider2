import type { Finding } from "@mod/authority-rules";
import { isUnavailable } from "@mod/kernel";
import { opIds } from "@mod/transparency-wire";
import { beforeEach, describe, expect, it } from "vitest";
import { memoryFrames } from "../../../test/fixtures/frames.ts";
import { logBook } from "../../../test/fixtures/log.ts";
import { allParts, issue, keyChange, owners } from "../../../test/fixtures/registrations.ts";
import type { Stage, TransparencyLog } from "../../contract.ts";
import { clientTending, transparencyOver } from "../driver.ts";

const flow = { of: "client", id: "c1" } as const;
const leaseMs = 5000;
const verified: Finding = { verdict: "verified", outcome: "took" };
const held: Finding = { verdict: "held", outcome: "took" };
const start = (op: string): Stage => ({
	kind: "start",
	flow,
	op,
	stage: 1,
	last: false,
	preimage: { v: 1, evidence: [], content: {} },
});
const bundle = (op: string): Stage => ({
	kind: "bundle",
	flow,
	op,
	stage: 2,
	last: true,
	tokens: [{ frame: "accessToken", digest: "A".repeat(43) }],
	preimage: { v: 1, evidence: [], content: {} },
});

let world: ReturnType<typeof makeWorld>;
function makeWorld() {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	const replica = (instance: string, wrap: (l: TransparencyLog) => TransparencyLog = (l) => l) =>
		transparencyOver({
			frames: store.frames,
			log: wrap(log.as(instance)),
			kinds: [issue, keyChange],
			owners,
			leaseMs,
		});
	const unit = (op: string) => ({ flow, op });
	const frame = (op: string) =>
		store.value(unit(op) as never) as
			| { applied: number; intent: Record<string, unknown> | null }
			| undefined;
	const listed = () =>
		store.frames.flowRecord(flow).then((v) => (v as { open?: string[] } | undefined)?.open ?? []);
	return { store, log, replica, w1: replica("w1"), w2: replica("w2"), frame, listed };
}
beforeEach(() => {
	world = makeWorld();
});

const decide = (op: string, who = world.w1) =>
	who.decide({
		kind: "issue",
		flow,
		op,
		decide: () => ({ digest: "d".repeat(43), eff: {}, records: [] }),
	});
/** An op's start and bundle, sent by its owner, each appended with no previous position. */
async function sendBoth(op: string, who = world.w1) {
	await who.send({ flow, op, stage: start(op), prev: 0 });
	return who.send({ flow, op, stage: bundle(op), prev: 0 });
}

describe("a client's flow: one frame per op, unconditional appends (KG-07)", () => {
	it("decides each op in its own frame: another op of the client is never refused as open", async () => {
		expect(await decide("o1")).toEqual({ prev: 0 });
		expect(await decide("o2", world.w2)).toEqual({ prev: 0 });
		expect(world.frame("o1")).toMatchObject({ intent: { op: "o1", state: "pending", by: "w1" } });
		expect(world.frame("o2")).toMatchObject({ intent: { op: "o2", state: "pending", by: "w2" } });
		// An op is never decided twice, open or ended; each open one is listed in its flow's record.
		expect(await decide("o1", world.w2)).toEqual({ refused: "ended" });
		expect(await world.listed()).toEqual(["o1", "o2"]);
	});

	it("looks on from the flow's head when decided, and appends with no previous position", async () => {
		await decide("o0");
		await sendBoth("o0");
		expect(await decide("o1")).toEqual({ prev: 2 });
		expect(world.frame("o1")).toMatchObject({ applied: 2 });
		await sendBoth("o1");
		expect(world.log.sent.every((s) => !("prev" in s))).toBe(true);
	});

	it("takes in its owner's stages, passing over another op's records unjudged, and ends it took", async () => {
		await decide("o1");
		await decide("o2", world.w2);
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		await world.w2.send({ flow, op: "o2", stage: start("o2"), prev: 0 });
		await world.w1.send({ flow, op: "o1", stage: bundle("o1"), prev: 0 });
		world.log.judge(flow, 1, verified);
		expect(await world.w1.step({ flow, own: "o1" })).toEqual({ position: 1 });
		expect(await world.w1.step({ flow, own: "o1" })).toEqual({ refused: "unjudged" });
		world.log.judge(flow, 3, verified);
		expect(await world.w2.step({ flow, own: "o1" })).toEqual({ refused: "waits" });
		expect(await world.w1.step({ flow, own: "o1" })).toEqual({
			position: 3,
			end: { op: "o1", kind: "issue", ending: "took", owner: true },
		});
		// Ended, it leaves its flow's list and its frame is dropped in the same write.
		expect(world.frame("o1")).toBeUndefined();
		expect(await world.listed()).toEqual(["o2"]);
		expect(world.frame("o2")).toMatchObject({ applied: 0, intent: { state: "pending" } });
		// Its frame dropped, nothing of it is taken in again.
		expect(await world.w1.step({ flow, own: "o1" })).toEqual({ refused: "stuck" });
	});

	it("ends a held bundle held, its owner told", async () => {
		await decide("o1");
		await sendBoth("o1");
		world.log.judge(flow, 1, verified);
		world.log.judge(flow, 2, held);
		await world.w1.step({ flow, own: "o1" });
		expect(await world.w1.step({ flow, own: "o1" })).toMatchObject({
			end: { ending: "held", owner: true },
		});
		expect([world.frame("o1"), await world.listed()]).toEqual([undefined, []]);
	});

	it("closes its op without a record on `abandoned` alone; any other refusal leaves it to its lease's end", async () => {
		type Refusal = "temporary" | "lateBundle" | "sameIdOther" | "evidenceUsed" | "abandoned";
		const refusing = (refusal: Refusal) =>
			world.replica("w1", (l) => ({
				...l,
				append: async () => ({ v: 1, result: "refused", refusal }),
			}));
		await decide("o1");
		for (const refusal of ["temporary", "lateBundle", "sameIdOther", "evidenceUsed"] as const) {
			expect(await refusing(refusal).send({ flow, op: "o1", stage: start("o1"), prev: 0 })).toEqual(
				{ answer: { v: 1, result: "refused", refusal } },
			);
			expect(world.frame("o1")).toMatchObject({ intent: { state: "pending" } });
		}
		expect(await world.listed()).toEqual(["o1"]);
		expect(
			await refusing("abandoned").send({ flow, op: "o1", stage: bundle("o1"), prev: 0 }),
		).toMatchObject({ end: { op: "o1", ending: "refused", owner: true } });
		expect([world.frame("o1"), await world.listed()]).toEqual([undefined, []]);
	});

	it("never decides again an op closed with no record, though its frame is dropped", async () => {
		const refusing = world.replica("w1", (l) => ({
			...l,
			append: async () => ({ v: 1, result: "refused", refusal: "abandoned" }),
		}));
		await decide("o1");
		expect(await refusing.send({ flow, op: "o1", stage: start("o1"), prev: 0 })).toMatchObject({
			end: { op: "o1", ending: "refused" },
		});
		expect([world.frame("o1"), world.log.records(flow)]).toEqual([undefined, []]);
		expect(await decide("o1", world.w2)).toEqual({ refused: "ended" });
		expect(world.frame("o1")).toBeUndefined();
	});

	it("rebases with no position to move, or closes its op once a stage is placed", async () => {
		await decide("o1");
		expect(await world.w1.rebase({ flow, op: "o1", recheck: () => false })).toEqual({
			refused: "unplaced",
		});
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		expect(await world.w2.rebase({ flow, op: "o1", recheck: () => false })).toEqual({
			refused: "notOwner",
		});
		expect(await world.w1.rebase({ flow, op: "o1", recheck: () => true })).toEqual({ prev: 0 });
		expect(await world.w1.rebase({ flow, op: "o1", recheck: () => false })).toEqual({
			end: { op: "o1", kind: "issue", ending: "refused", owner: true },
		});
		expect([world.frame("o1"), await world.listed()]).toEqual([undefined, []]);
	});
});

describe("tending a client's flow: each op its record lists, its own unit", () => {
	it("abandons a bundle left alone with an unconditional record, and closes once it is verified", async () => {
		await decide("o1");
		await sendBoth("o1");
		world.log.judge(flow, 1, verified);
		world.log.judge(flow, 2, verified);
		world.store.clock.set(leaseMs);
		expect(await world.w2.tend(flow)).toMatchObject({
			stepped: 2,
			did: "abandonment",
			answer: { result: "accepted", position: 3 },
		});
		expect(world.frame("o1")).toMatchObject({ intent: { state: "abandoning", by: "w2" } });
		const sent = world.log.sent.at(-1);
		expect(sent).toMatchObject({ stage: { op: opIds.abandonment("o1", 1), flow } });
		expect(sent && "prev" in sent).toBe(false);
		// The owner, back late, gives no output: its lease ended before the bundle was taken in.
		expect(await world.w1.step({ flow, own: "o1" })).toEqual({ refused: "unjudged" });
		world.log.judge(flow, 3, verified);
		await world.w2.tend(flow);
		expect([world.frame("o1"), await world.listed()]).toEqual([undefined, []]);
	});

	it("marks an orphan with its start alone, then sends its abandonment; a held one is sent again", async () => {
		await decide("o1");
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		world.log.judge(flow, 1, verified);
		world.store.clock.set(leaseMs);
		expect(await world.w2.tend(flow)).toEqual({ stepped: 1, did: "marked" });
		expect(await world.w2.tend(flow)).toMatchObject({ stepped: 0, did: "abandonment" });
		world.log.judge(flow, 2, held);
		expect(await world.w2.tend(flow)).toMatchObject({ stepped: 1, did: "abandonment" });
		expect(world.log.records(flow).map((p) => p.record.op)).toEqual([
			"o1",
			opIds.abandonment("o1", 1),
			opIds.abandonment("o1", 2),
		]);
	});

	it("closes, by rounds of tending the client flows, an op whose owner fell with no writer asking", async () => {
		const other = { of: "client", id: "c2" } as const;
		await decide("o1");
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		await world.w1.decide({
			kind: "issue",
			flow: other,
			op: "o2",
			decide: () => ({ digest: "d".repeat(43), eff: {}, records: [] }),
		});
		world.log.judgeOnAppend(verified);
		world.log.judge(flow, 1, verified);
		world.store.clock.set(leaseMs);
		for (let round = 0; round < 3; round++) await clientTending(world.w2, world.store.frames);
		expect([world.frame("o1"), await world.listed()]).toEqual([undefined, []]);
		expect(world.log.records(other).map((p) => p.record.op)).toEqual([opIds.abandonment("o2", 1)]);
		expect(await world.store.frames.flowRecord(other)).toMatchObject({ open: [] });
	});

	it("claims nothing of an op whose own record is unjudged, nor of a live owner's", async () => {
		await decide("o1");
		await sendBoth("o1");
		expect(await world.w2.tend(flow)).toEqual({ stepped: 0 });
		world.store.clock.set(leaseMs);
		expect(await world.w2.tend(flow)).toEqual({ stepped: 0 });
		expect(world.frame("o1")).toMatchObject({ intent: { state: "pending" } });
	});

	it("refuses an event naming no op of a client's flow, and any on a flow neither a subject's nor a client's", async () => {
		expect(await world.w1.step({ flow })).toEqual({ refused: "notSubject" });
		expect(
			await world.w1.changeHeld({ kind: "issue", flow, records: [], change: () => [] }),
		).toEqual({ refused: "notSubject" });
		const publisher = { of: "publisher", id: "p" } as const;
		expect(await world.w1.tend(publisher)).toEqual({ refused: "notSubject" });
		expect(
			await world.w1.decide({
				kind: "issue",
				flow: publisher,
				op: "o",
				decide: () => ({ digest: "d".padEnd(43, "0"), eff: {}, records: [] }),
			}),
		).toEqual({ refused: "notSubject" });
	});
});

describe("tending a client's flow by the ops its record lists, however far back", () => {
	it("closes a bundle left alone though 64 later records pushed it back, and an op that fell before its first append", async () => {
		await decide("old");
		await sendBoth("old");
		await decide("silent");
		for (let i = 0; i < 40; i++) {
			await decide(`busy${i}`, world.w2);
			await sendBoth(`busy${i}`, world.w2);
		}
		for (const p of world.log.records(flow)) world.log.judge(flow, p.record.position, verified);
		// The busy ops' owner takes each in, so they end and leave the list.
		for (let i = 0; i < 40; i++) {
			await world.w2.step({ flow, own: `busy${i}` });
			await world.w2.step({ flow, own: `busy${i}` });
		}
		expect(await world.listed()).toEqual(["old", "silent"]);
		world.store.clock.set(leaseMs);
		// The first turn marks the silent op and abandons the old bundle; the next sends the silent op's.
		await world.w2.tend(flow);
		await world.w2.tend(flow);
		const abandoned = world.log.records(flow).filter((p) => p.record.kind === "abandonment");
		expect(abandoned.map((p) => p.record.abandons?.op).sort()).toEqual(["old", "silent"]);
		for (const p of abandoned) world.log.judge(flow, p.record.position, verified);
		await world.w2.tend(flow);
		expect([world.frame("old"), world.frame("silent")]).toEqual([undefined, undefined]);
		expect(await world.listed()).not.toContain("old");
		expect(await world.listed()).not.toContain("silent");
		// Closed by their abandonments, frames dropped, neither is decided again.
		expect(await decide("silent")).toEqual({ refused: "ended" });
		expect(await decide("old")).toEqual({ refused: "ended" });
	});

	it("goes round the list, so 64 ops it cannot close at its head never keep it from the one behind", async () => {
		for (let i = 0; i < 64; i++) {
			await decide(`stuck${i}`, world.w2);
			await world.w2.send({ flow, op: `stuck${i}`, stage: start(`stuck${i}`), prev: 0 });
		}
		await decide("late");
		await world.w1.send({ flow, op: "late", stage: start("late"), prev: 0 });
		world.log.judge(flow, 65, verified);
		world.store.clock.set(leaseMs);
		// The stuck ops' own records stay unjudged: each turn takes nothing in of them and claims none.
		for (let turn = 0; turn < 4 && world.frame("late") !== undefined; turn++) {
			await world.w2.tend(flow);
			for (const p of world.log.records(flow).filter((r) => r.record.kind === "abandonment"))
				world.log.judge(flow, p.record.position, verified);
		}
		expect(world.frame("late")).toBeUndefined();
		expect(await world.listed()).toHaveLength(64);
		expect(await world.listed()).not.toContain("late");
	});
});

describe("a client's flow with a record off the wire's form", () => {
	it("tends every other op of the turn, then answers unavailable", async () => {
		await decide("o1");
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		await decide("o2");
		await world.w1.send({ flow, op: "o2", stage: start("o2"), prev: 0 });
		world.log.judge(flow, 1, verified);
		world.log.judge(flow, 2, verified);
		// o1's own record, as an adapter that does not hold what it answers to the wire's form gives it.
		const off = world.replica("w1", (l) => ({
			...l,
			writer: l.writer,
			digest: l.digest,
			append: l.append,
			head: l.head,
			of: l.of,
			reset: l.reset,
			at: async (f, position) => {
				const placed = await l.at(f, position);
				return placed && position === 1
					? ({ ...placed, record: { ...placed.record, v: 2 } } as never)
					: placed;
			},
		}));
		await expect(off.tend(flow)).rejects.toSatisfy(isUnavailable);
		// o2, behind it in the turn, was tended all the same: its own record taken in.
		expect(world.frame("o2")).toMatchObject({ applied: 2 });
		expect(world.frame("o1")).toMatchObject({ applied: 0 });
	});

	it("answers unavailable for a well-formed record of another flow or position than asked", async () => {
		await decide("o1");
		await world.w1.send({ flow, op: "o1", stage: start("o1"), prev: 0 });
		world.log.judge(flow, 1, verified);
		const elsewhere = world.replica("w9", (l) => ({
			...l,
			writer: l.writer,
			digest: l.digest,
			append: l.append,
			head: l.head,
			of: l.of,
			reset: l.reset,
			at: async (f, position) => {
				const placed = await l.at(f, position);
				return (
					placed &&
					({ ...placed, record: { ...placed.record, flow: { of: "client", id: "c9" } } } as never)
				);
			},
		}));
		await expect(elsewhere.step({ flow, own: "o1" })).rejects.toSatisfy(isUnavailable);
		expect(world.frame("o1")).toMatchObject({ applied: 0 });
	});
});
