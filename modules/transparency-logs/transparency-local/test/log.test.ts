import type { Stage } from "@mod/transparency";
import { type AppendAnswer, logTyps, schemas } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { abandonment, boot, subjectFlow, testClock } from "./fixtures/world.ts";

const accepted = (answer: AppendAnswer) => {
	if (answer.result !== "accepted") throw new Error(`refused: ${answer.refusal}`);
	return answer;
};
/** A receipt's protected header and payload, as read from its compact form. */
const readReceipt = (receipt: string) => {
	const [header, payload] = receipt
		.split(".")
		.slice(0, 2)
		.map((part) => JSON.parse(Buffer.from(part, "base64url").toString()));
	return { header, payload };
};

describe("transparency-local's log (t0)", () => {
	it("places a subject flow's stage after the previous position, numbered by the store", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		expect(await log.head(flow)).toBe(0);
		const first = accepted(await log.append(abandonment(flow), 0));
		const second = accepted(await log.append(abandonment(flow), 1));
		expect([first.position, second.position]).toEqual([1, 2]);
		expect([first.n, second.n]).toEqual([1, 2]);
		expect(first.shard).toBe(second.shard);
		expect(await log.head(flow)).toBe(2);
		expect(await log.head(subjectFlow())).toBe(0);
	});

	it("answers each append with the wire's form, and keeps a record the wire's schema reads", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const answer = await log.append(abandonment(flow), 0);
		expect(schemas.appendAnswer.parse(answer)).toEqual(answer);
		const placed = await log.at(flow, 1);
		expect(schemas.record.parse(placed?.record)).toEqual(placed?.record);
		expect(placed?.record).toMatchObject({ id: accepted(answer).id, position: 1 });
		expect(await log.at(flow, 2)).toBeUndefined();
	});

	it("takes the acceptance time from the kernel's clock", async () => {
		const clock = testClock();
		const { log } = await boot({ clock });
		const flow = subjectFlow();
		const answer = accepted(await log.append(abandonment(flow), 0));
		expect(answer.acceptedAt).toBe(clock.now());
		clock.move(5_000);
		expect(accepted(await log.append(abandonment(flow), 1)).acceptedAt).toBe(clock.now());
	});

	it("refuses an append after another position than the flow's head, placing nothing", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		expect(await log.append(abandonment(flow), 1)).toEqual({
			v: 1,
			result: "refused",
			refusal: "prevMismatch",
		});
		expect(await log.head(flow)).toBe(0);
	});

	it("places one of two appends after the same position, and refuses the other", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const answers = await Promise.all([
			log.append(abandonment(flow), 0),
			log.append(abandonment(flow), 0),
		]);
		expect(answers.map((a) => a.result).sort()).toEqual(["accepted", "refused"]);
		expect(answers.find((a) => a.result === "refused")).toMatchObject({ refusal: "prevMismatch" });
		expect(await log.head(flow)).toBe(1);
	});

	it("answers an op's stage placed already with the same content by its first answer, before the previous position", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const stage = abandonment(flow);
		const first = accepted(await log.append(stage, 0));
		await log.append(abandonment(flow), 1);
		expect(await log.append(stage, 0)).toEqual(first);
		expect(await log.head(flow)).toBe(2);
	});

	it("refuses an op's stage placed already with other content", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const stage = abandonment(flow);
		await log.append(stage, 0);
		const other = { ...stage, preimage: { ...stage.preimage, content: { other: true } } };
		expect(await log.append(other, 1)).toEqual({
			v: 1,
			result: "refused",
			refusal: "sameIdOther",
		});
	});

	it("places a client's flow's stages with no previous position, each at the head", async () => {
		const { log } = await boot();
		const flow = { of: "client", id: "c1" } as const;
		const answers = await Promise.all([
			log.append(abandonment(flow)),
			log.append(abandonment(flow)),
		]);
		expect(answers.map((a) => accepted(a).position).sort()).toEqual([1, 2]);
	});

	it("takes a previous position on a conditional flow alone, as the wire does", async () => {
		const { log } = await boot();
		await expect(log.append(abandonment(subjectFlow()))).rejects.toThrow(TypeError);
		await expect(log.append(abandonment({ of: "client", id: "c1" }), 0)).rejects.toThrow(TypeError);
	});

	it("refuses a stage naming a version, which no flow of its holds a window for", async () => {
		const { log } = await boot();
		const stage = { ...abandonment(subjectFlow()), registryVersion: 1 };
		await expect(log.append(stage, 0)).rejects.toThrow(/version/);
	});

	it("tells what a flow holds of an op: its stages, its last, its abandonments", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const abandoned = "op-left";
		await log.append(abandonment(flow, abandoned, 1), 0);
		await log.append(abandonment(flow, abandoned, 2), 1);
		expect(await log.of(flow, abandoned)).toEqual({ stages: 0, last: false, abandonments: 2 });
		const own = abandonment(flow, abandoned, 1).op;
		expect(await log.of(flow, own)).toEqual({ stages: 1, last: true, abandonments: 0 });
		expect(await log.of(flow, "none")).toEqual({ stages: 0, last: false, abandonments: 0 });
	});

	it("gives one receipt of the wire's receipt for a record of no token, unsigned", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const answer = accepted(await log.append(abandonment(flow), 0));
		expect(answer.receipts).toHaveLength(1);
		const { header, payload } = readReceipt(answer.receipts[0] ?? "");
		expect(header).toEqual({ alg: "none", typ: logTyps.receipt });
		expect(schemas.receipt.parse(payload)).toMatchObject({
			id: answer.id,
			flow,
			position: 1,
			kind: "abandonment",
			acceptedAt: answer.acceptedAt,
		});
	});

	it("gives a bundle one receipt per token, in order, each naming its token", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const tokens = [
			{ frame: "accessToken", digest: "a".repeat(43) },
			{ frame: "family", digest: "f".repeat(43) },
		] as const;
		const { abandons: _none, ...stage } = abandonment(flow);
		const bundle: Stage = { ...stage, kind: "bundle", op: "o1", stage: 2, tokens: [...tokens] };
		const answer = accepted(await log.append(bundle, 0));
		expect(answer.receipts.map((r) => readReceipt(r).payload.token)).toEqual(tokens);
	});

	it("gives the preimage's digest its append names, the same for the same content in any order", async () => {
		const { log } = await boot();
		const flow = subjectFlow();
		const stage = abandonment(flow);
		await log.append(stage, 0);
		const placed = await log.at(flow, 1);
		expect(placed?.record.plaintextDigest).toBe(log.digest(stage.preimage));
		const reordered = { content: {}, evidence: [], v: 1 as const };
		expect(log.digest(reordered)).toBe(log.digest(stage.preimage));
	});
});
