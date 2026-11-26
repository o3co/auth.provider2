import type { Finding } from "@mod/authority-rules";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type LogStore, logStore } from "../src/contract.ts";
import type { Judging } from "../src/judging.ts";
import { localLog } from "../src/log.ts";
import { abandonment, boot, subjectFlow } from "./fixtures/world.ts";

const took: Finding = { verdict: "verified", outcome: "took" };

/** A judgment a test gives, counting each record it is asked of by its id. */
function judgingAs(finding: Finding = took) {
	const asked: string[] = [];
	const judging: Judging = async (record) => {
		asked.push(record.id);
		const { id, kind, op, stage, last, position, acceptedAt } = record;
		return {
			envelope: { id, kind, op, stage, last, position, acceptedAt },
			changes: {},
			judgment: finding,
		};
	};
	return { asked, judging };
}

/** The log over the memory store, its writes passed through `write` where a test gives one. */
async function over(
	write?: (
		real: LogStore["write"],
		...args: Parameters<LogStore["write"]>
	) => ReturnType<LogStore["write"]>,
) {
	const { app } = await boot();
	const store = await app.get(logStore);
	const faulty: LogStore = write
		? { read: store.read, write: (...args) => write(store.write, ...args) }
		: store;
	let n = 0;
	const logAs = (instance: string, judging: Judging) =>
		localLog({
			store: faulty,
			writer: { instance, generation: 1 },
			now: () => 1_000,
			id: () => {
				n += 1;
				return `${instance}-${n}`;
			},
			judging,
			// No reset is placed here: no installation, so each is `invalid` before any of these is read.
			resetting: {
				newest: undefined,
				checks: undefined as never,
				context: {} as never,
				judging: () => {
					throw new TypeError("no reset here");
				},
			},
		});
	return { logAs };
}

describe("transparency-local's log under a failing store", () => {
	it("answers temporary after 8 lost races, writing nothing; each try judges the stage it has not placed", async () => {
		const { logAs } = await over(async () => "moved");
		const { asked, judging } = judgingAs();
		const log = logAs("w1", judging);
		const flow = subjectFlow();
		expect(await log.append(abandonment(flow), 0)).toEqual({
			v: 1,
			result: "refused",
			refusal: "temporary",
		});
		expect(asked).toHaveLength(8);
		expect(await log.head(flow)).toBe(0);
	});

	it("tries again after a write past its deadline, placing the record its next try judged", async () => {
		let late = true;
		const { logAs } = await over(async (real, ...args) => {
			if (!late) return real(...args);
			late = false;
			return "late";
		});
		const { asked, judging } = judgingAs();
		const log = logAs("w1", judging);
		const flow = subjectFlow();
		const answer = await log.append(abandonment(flow), 0);
		expect(answer).toMatchObject({ result: "accepted", position: 1, id: asked[1] });
		expect(asked).toHaveLength(2);
		expect(await log.head(flow)).toBe(1);
	});

	it("answers a resend after a write's Unavailable, which applied, with the first answer, judging nothing again", async () => {
		let lost = true;
		const { logAs } = await over(async (real, ...args) => {
			const written = await real(...args);
			if (!lost) return written;
			lost = false;
			throw new Unavailable("store");
		});
		const { asked, judging } = judgingAs();
		const log = logAs("w1", judging);
		const flow = subjectFlow();
		const stage = abandonment(flow);
		expect(await log.append(stage, 0).catch((e: unknown) => isUnavailable(e))).toBe(true);
		const resent = await log.append(stage, 0);
		expect(resent).toMatchObject({ result: "accepted", position: 1, id: asked[0] });
		expect(asked).toHaveLength(1);
	});

	it("keeps a placed record and its finding across a restart: another replica reads it, judging it never again", async () => {
		const { logAs } = await over();
		const before = judgingAs(took);
		const flow = subjectFlow();
		const stage = abandonment(flow);
		const first = await logAs("w1", before.judging).append(stage, 0);
		const after = judgingAs({ verdict: "forged", outcome: "didNotTake" });
		const restarted = logAs("w2", after.judging);
		expect(await restarted.head(flow)).toBe(1);
		expect((await restarted.at(flow, 1))?.finding).toEqual(took);
		expect(await restarted.append(stage, 0)).toEqual(first);
		expect(after.asked).toHaveLength(0);
		expect(await restarted.append(abandonment(flow), 1)).toMatchObject({ position: 2 });
		expect((await restarted.at(flow, 2))?.finding).toEqual({
			verdict: "forged",
			outcome: "didNotTake",
		});
	});
});

// Two replicas over one store: here, where the helper giving a second writer over one store lives.
describe("transparency-local's log, appended to by two replicas", () => {
	it("answers another replica's resend of a placed stage as first placed, though a record came after it", async () => {
		// The writer is not part of the content: a taker's resend (KE-C10) is the same stage.
		const { logAs } = await over();
		const w1 = logAs("w1", judgingAs().judging);
		const w2 = logAs("w2", judgingAs().judging);
		const flow = subjectFlow();
		const stage = abandonment(flow);
		const first = await w1.append(stage, 0);
		expect(await w1.append(abandonment(flow), 1)).toMatchObject({ position: 2 });
		expect(await w2.append(stage, 0)).toEqual(first);
		const other = { ...stage, preimage: { ...stage.preimage, content: { other: true } } };
		expect(await w2.append(other, 2)).toEqual({
			v: 1,
			result: "refused",
			refusal: "sameIdOther",
		});
		expect(await w2.head(flow)).toBe(2);
	});

	it("places one record when two replicas append the same stage at once, each answered as first placed", async () => {
		// Two replicas sending one abandonment (KE-C09, any replica): one record, both answered alike.
		const writes: unknown[] = [];
		const { logAs } = await over(async (real, ...args) => {
			const written = await real(...args);
			writes.push(written);
			return written;
		});
		const held: Finding = { verdict: "held", outcome: "took" };
		const w1 = logAs("w1", judgingAs(took).judging);
		const w2 = logAs("w2", judgingAs(held).judging);
		const flow = subjectFlow();
		const stage = abandonment(flow);
		const [a, b] = await Promise.all([w1.append(stage, 0), w2.append(stage, 0)]);
		expect(a).toMatchObject({ result: "accepted", position: 1 });
		expect(b).toEqual(a);
		// Both judged before either wrote; the record keeps its winner's judgment alone.
		const winner = "id" in a && String(a.id).startsWith("w1") ? took : held;
		expect((await w1.at(flow, 1))?.finding).toEqual(winner);
		// They raced: one write lost to the other's, its next try finding the stage placed.
		expect(writes.filter((w) => w === "moved")).toHaveLength(1);
		expect(await w1.head(flow)).toBe(1);
	});
});
