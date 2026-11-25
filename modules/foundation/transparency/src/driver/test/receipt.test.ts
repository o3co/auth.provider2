import { beforeEach, describe, expect, it } from "vitest";
import { memoryFrames } from "../../../test/fixtures/frames.ts";
import { logBook } from "../../../test/fixtures/log.ts";
import { allParts, issue, owners, seeded } from "../../../test/fixtures/registrations.ts";
import type { Json, Stage } from "../../contract.ts";
import { transparencyOver } from "../driver.ts";

const flow = { of: "subject", id: "s1" } as const;
const stageOf = (op: string, content = "code"): Stage => ({
	kind: "bundle",
	flow,
	op,
	stage: 1,
	last: true,
	tokens: [{ frame: "accessToken", digest: "A".repeat(43) }],
	preimage: { v: 1, evidence: [], content: { via: content } },
});

function makeWorld() {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	const replica = (instance: string) =>
		transparencyOver({
			frames: store.frames,
			log: log.as(instance),
			kinds: [issue],
			owners,
			leaseMs: 5000,
		});
	for (const [part, value] of Object.entries(seeded))
		store.put(flow, { part, name: "state" }, value as unknown as Json);
	return { store, log, w1: replica("w1"), w2: replica("w2") };
}
let world: ReturnType<typeof makeWorld>;
beforeEach(() => {
	world = makeWorld();
});

/** An op decided and its one stage sent by w1. */
async function placed(op: string) {
	const decided = await world.w1.decide({
		kind: "issue",
		flow,
		op,
		decide: () => ({ digest: "d1", eff: {}, records: [] }),
	});
	if (!("prev" in decided)) throw new Error(decided.refused);
	return world.w1.send({ flow, op, stage: stageOf(op), prev: decided.prev });
}

describe("a stage's receipt asked again", () => {
	it("answers a stage the log placed as it first answered, by any replica, writing no frame", async () => {
		const sent = await placed("op1");
		if (!("answer" in sent)) throw new Error(sent.refused);
		const frame = structuredClone(world.store.value(flow));
		const again = await world.w2.receiptOf({ flow, op: "op1", stage: stageOf("op1") });
		expect(again).toEqual({ answer: sent.answer });
		expect(world.store.value(flow)).toEqual(frame);
		expect(world.log.records(flow)).toHaveLength(1);
	});

	it("places nothing for a stage the log does not hold, decided or not, and appends nothing", async () => {
		await world.w1.decide({
			kind: "issue",
			flow,
			op: "op1",
			decide: () => ({ digest: "d1", eff: {}, records: [] }),
		});
		const frame = structuredClone(world.store.value(flow));
		for (const op of ["op1", "op2"])
			expect(await world.w2.receiptOf({ flow, op, stage: stageOf(op) })).toEqual({
				refused: "unplaced",
			});
		expect(world.log.sent).toEqual([]);
		expect(world.log.records(flow)).toEqual([]);
		expect(world.store.value(flow)).toEqual(frame);
	});

	it("answers the log's own refusal for the same id with other content, placing nothing", async () => {
		await placed("op1");
		expect(await world.w2.receiptOf({ flow, op: "op1", stage: stageOf("op1", "other") })).toEqual({
			answer: { v: 1, result: "refused", refusal: "sameIdOther" },
		});
		expect(world.log.records(flow)).toHaveLength(1);
	});

	it("refuses a stage of a later number than the log holds, and one naming another op or flow", async () => {
		await placed("op1");
		const second = { ...stageOf("op1"), stage: 2 };
		expect(await world.w2.receiptOf({ flow, op: "op1", stage: second })).toEqual({
			refused: "unplaced",
		});
		await expect(world.w2.receiptOf({ flow, op: "op2", stage: stageOf("op1") })).rejects.toThrow(
			TypeError,
		);
		const elsewhere = { ...stageOf("op1"), flow: { of: "subject", id: "s2" } } as Stage;
		await expect(world.w2.receiptOf({ flow, op: "op1", stage: elsewhere })).rejects.toThrow(
			TypeError,
		);
		expect(
			await world.w2.receiptOf({
				flow: { of: "monitor", id: "m" } as never,
				op: "op1",
				stage: stageOf("op1"),
			}),
		).toEqual({ refused: "notSubject" });
		expect(world.log.records(flow)).toHaveLength(1);
	});

	it("places no stage of an op whose other stage alone the log holds, nor any on a client's flow", async () => {
		// Stage 2 alone on the log: the op holds a stage, but not the one asked.
		await world.log.as("w9").append({ ...stageOf("op1"), stage: 2 }, 0);
		expect(await world.w2.receiptOf({ flow, op: "op1", stage: stageOf("op1") })).toEqual({
			refused: "unplaced",
		});
		expect(world.log.records(flow)).toHaveLength(1);
		const client = { of: "client", id: "c1" } as const;
		expect(
			await world.w2.receiptOf({
				flow: client,
				op: "op1",
				stage: { ...stageOf("op1"), flow: client },
			}),
		).toEqual({ refused: "notSubject" });
		expect(world.log.records(client)).toEqual([]);
	});
});
