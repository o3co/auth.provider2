import { hpke, typs } from "@mod/sdk-core-wire";
import { type Stage, transparency, transparencyLog } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import { issued, items, payloadOf, possessionItems } from "../../../test/fixtures/statements.ts";
import { openSealed, screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import { recordOf } from "../../record/record.ts";
import { approvalKind, deciding } from "../completion.ts";

describe("completing an authorization", () => {
	async function approved() {
		const w = await world();
		const key = await w.plant("s1");
		const keys = screenKeys();
		const t = await w.approvals.issue({
			purpose: "authorization",
			items,
			screen: keys.screen,
			by: "src",
		});
		if (t.kind !== "issued") throw new Error(t.reason);
		const assertion = w.assert(t.challenge);
		const used = await w.approvals.use({ statement: t.statement, assertion });
		if (used.kind !== "approved") throw new Error(used.reason);
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		return { w, key, keys, t, assertion };
	}

	it("puts the approval on the subject's flow, then signs the completion and seals it to the screen", async () => {
		const { w, keys, t, assertion } = await approved();
		const done = await w.approvals.complete({ hash: t.hash, code: "code-1" });
		if (done.kind !== "completed") throw new Error(done.reason);
		const [record] = w.book.records({ of: "subject", id: "s1" });
		expect(record?.record).toMatchObject({
			kind: "approval",
			op: `approval:${t.hash}`,
			last: true,
			approval: {
				statement: sha256(t.statement),
				assertion: sha256(assertion),
				code: sha256("code-1"),
			},
		});
		const jws = openSealed(
			keys.encKey,
			done,
			hpke.info.completion,
			hpke.completionAad("authorization", t.hash),
		);
		// Under the bare hash, or another purpose's additional data, it does not open.
		for (const other of [t.hash, hpke.completionAad("first-key", t.hash)]) {
			expect(() => openSealed(keys.encKey, done, hpke.info.completion, other)).toThrow();
		}
		expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
		expect(payloadOf(jws)).toMatchObject({
			t_hash: t.hash,
			assertion_hash: sha256(assertion),
			code: "code-1",
		});
		const state = w.frames.value({ of: "subject", id: "s1" }, { part: "approvals", name: "state" });
		expect(state).toMatchObject({ consumed: [`statement:${payloadOf(t.statement).sid}`] });
		expect(Object.values((state as { approvals: object }).approvals)).toEqual([
			expect.objectContaining({ code: sha256("code-1"), client: "c1" }),
		]);
		expect(done.record).toBe(record?.record.id);
		// Its reference on the log, as an ID token's `apr` names it.
		expect(done.ref).toEqual({ shard: record?.record.shard, n: record?.record.n });
		expect(done.acceptedAt).toBe(record?.record.acceptedAt);
		// Given again only once its caller let it go out.
		expect(await w.approvals.completionOf(t.hash)).toBeUndefined();
		expect(await w.approvals.publish(t.hash)).toBe("published");
		expect(await w.approvals.completionOf(t.hash)).toEqual(done);
		expect(await w.approvals.usedOf(t.hash)).toMatchObject({ completed: true });
		expect(await w.approvals.complete({ hash: t.hash, code: "code-1" })).toEqual(done);
		expect(await w.approvals.complete({ hash: t.hash, code: "code-2" })).toEqual({
			kind: "refused",
			reason: "code",
		});
		expect(w.book.records({ of: "subject", id: "s1" })).toHaveLength(1);
	});

	it("answers nothing for an approval not taken in", async () => {
		const { w, t } = await approved();
		w.book.judgeOnAppend({ verdict: "held", outcome: "didNotTake" });
		const done = await w.approvals.complete({ hash: t.hash, code: "code-1" });
		expect(done).toEqual({ kind: "refused", reason: "ended" });
	});

	it("lets an orphan, left before its stage was sent, be abandoned, and completes it again after", async () => {
		const { w, keys, t } = await approved();
		const flow = { of: "subject", id: "s1" } as const;
		const tr = await w.app.get(transparency);
		const r = recordOf(await w.statements.store.read(t.hash));
		if (!r) throw new Error("no record");
		const decide = deciding(
			r,
			"code-1",
			(pre) => sha256(JSON.stringify(pre)),
			() => {},
		);
		const op = `approval:${t.hash}`;
		expect(await tr.decide({ kind: approvalKind.name, flow, op, decide })).toHaveProperty("prev");
		w.frames.clock.set(w.frames.clock.now() + 6000);
		const turns = [await tr.tend(flow), await tr.tend(flow), await tr.tend(flow)];
		expect(turns.map((turn) => "did" in turn && turn.did)).toContain("marked");
		expect(turns.map((turn) => "did" in turn && turn.did)).toContain("abandonment");
		expect(w.book.records(flow).map((p) => p.record.kind)).toEqual(["abandonment"]);
		const done = await w.approvals.complete({ hash: t.hash, code: "code-1" });
		if (done.kind !== "completed") throw new Error(done.reason);
		expect(
			openSealed(
				keys.encKey,
				done,
				hpke.info.completion,
				hpke.completionAad("authorization", t.hash),
			),
		).toBeDefined();
		expect(w.book.records(flow).map((p) => p.record.kind)).toEqual(["abandonment", "approval"]);
	});

	it("takes in an orphan's stage once placed, and answers no completion for it", async () => {
		const { w, t } = await approved();
		const flow = { of: "subject", id: "s1" } as const;
		const tr = await w.app.get(transparency);
		const r = recordOf(await w.statements.store.read(t.hash));
		if (!r) throw new Error("no record");
		let stage: Stage | undefined;
		const digest = (await w.app.get(transparencyLog)).digest;
		const decide = deciding(r, "code-1", digest, (made) => {
			stage = made;
		});
		const op = `approval:${t.hash}`;
		const decided = await tr.decide({ kind: approvalKind.name, flow, op, decide });
		if (!("prev" in decided) || !stage) throw new Error("not decided");
		expect(await tr.send({ flow, op, stage, prev: decided.prev })).toHaveProperty(
			"answer.result",
			"accepted",
		);
		w.frames.clock.set(w.frames.clock.now() + 6000);
		await tr.tend(flow);
		expect(w.book.records(flow).map((p) => p.record.kind)).toEqual(["approval"]);
		expect(await w.approvals.complete({ hash: t.hash, code: "code-1" })).toEqual({
			kind: "refused",
			reason: "ended",
		});
	});

	it("refuses an orphan's late stage once its abandonment is placed", async () => {
		const { w, t } = await approved();
		const flow = { of: "subject", id: "s1" } as const;
		const tr = await w.app.get(transparency);
		const r = recordOf(await w.statements.store.read(t.hash));
		if (!r) throw new Error("no record");
		let stage: Stage | undefined;
		const digest = (await w.app.get(transparencyLog)).digest;
		const decide = deciding(r, "code-1", digest, (made) => {
			stage = made;
		});
		const op = `approval:${t.hash}`;
		const decided = await tr.decide({ kind: approvalKind.name, flow, op, decide });
		if (!("prev" in decided) || !stage) throw new Error("not decided");
		w.frames.clock.set(w.frames.clock.now() + 6000);
		await tr.tend(flow);
		await tr.tend(flow);
		const late = await w.book.as("w1").append(stage, decided.prev);
		expect(late).toMatchObject({ result: "refused", refusal: "prevMismatch" });
		expect(w.book.records(flow).map((p) => p.record.kind)).toEqual(["abandonment"]);
	});

	it("puts nothing on the flow for a statement past its expiry", async () => {
		const { w, t } = await approved();
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.complete({ hash: t.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "expired",
		});
		expect(w.book.records({ of: "subject", id: "s1" })).toHaveLength(0);
	});

	it("refuses a statement not used, and one of another purpose", async () => {
		const w = await world();
		const t = await issued(w);
		expect(await w.approvals.completionOf(t.hash)).toBeUndefined();
		expect(await w.approvals.complete({ hash: t.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "unused",
		});
		const { screen } = screenKeys();
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen,
			by: "s",
		});
		if (p.kind !== "issued") throw new Error(p.reason);
		expect(await w.approvals.complete({ hash: p.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
	});
});
