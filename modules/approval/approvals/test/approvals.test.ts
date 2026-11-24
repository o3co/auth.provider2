import { defineModule } from "@mod/kernel";
import { challengeInput, continuationInput, hpke, typs } from "@mod/sdk-core-wire";
import { type Stage, transparency, transparencyLog } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import { approvalKind, deciding } from "../src/completion/completion.ts";
import { type IssueAsk, statementItems } from "../src/contract.ts";
import { recordOf } from "../src/statement/statement.ts";
import { openSealed, screenKeys, sha256, world } from "./fixtures/world.ts";

const items = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "openid",
	nonce: "n",
	code_challenge: "cc",
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	jar_hash: "jh",
} as const;
const creationItems = {
	account: "a***@example",
	evidence: "ev",
	ct_hash: "ct",
	subject: "s1",
	kg: 0,
	options: {
		user_id: "u",
		rp_id: "rp.example",
		exclude_credentials: [],
		algorithms: [-7 as const],
	},
};
const possessionItems = {
	creation_hash: "ch",
	key_jkt: "kZ8n9mX3tQ2vB7cY4wR1sE6uA0pL5dH9jF2gK8hN3oM",
	credential_id: "cred",
	reservation_id: "res",
};

const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

async function issued(w: Awaited<ReturnType<typeof world>>, ask?: Partial<IssueAsk>) {
	const { screen } = screenKeys();
	const answer = await w.approvals.issue({
		purpose: "authorization",
		items,
		screen,
		by: "src",
		...ask,
	} as IssueAsk);
	if (answer.kind !== "issued") throw new Error(answer.reason);
	return answer;
}

describe("issuing a statement", () => {
	it("signs it by the Core's ring as an approval, keyed by its hash, with the challenge a get() asks", async () => {
		const w = await world();
		const t = await issued(w);
		const verified = await w.keys.verify("core", t.statement, typs.statement);
		expect(verified).toMatchObject({ kind: "valid" });
		expect(payloadOf(t.statement)).toMatchObject({
			iss: "https://issuer.example",
			purpose: "authorization",
			approval: items,
		});
		expect(t.hash).toBe(sha256(t.statement));
		expect(t.challenge).toBe(sha256(challengeInput(t.statement, "get")));
		expect(w.statements.value(t.hash)).toMatchObject({ state: "issued", jws: t.statement });
	});

	it("refuses items no module fills, and items the schema refuses", async () => {
		const narrow = defineModule({ name: "narrow", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(statementItems).by(() => ({
				purpose: "authorization",
				names: Object.keys(items).filter((n) => n !== "dpop_jkt"),
				by: "narrow",
			})),
		]);
		const w = await world({ items: narrow });
		const { screen } = screenKeys();
		const ask = { purpose: "authorization", items, screen, by: "src" } as const;
		expect(await w.approvals.issue(ask)).toEqual({ kind: "refused", reason: "items" });
		const all = await world();
		const wrong = { ...ask, items: { ...items, response_type: "token" } } as unknown as IssueAsk;
		expect(await all.approvals.issue(wrong)).toEqual({ kind: "refused", reason: "items" });
	});

	it("counts its issuing by the caller's key", async () => {
		const w = await world({ approvals: { "issue-limit": 1 } });
		await issued(w);
		expect(await w.approvals.issue(await askOf())).toEqual({ kind: "refused", reason: "limited" });
		expect((await issued(w, { by: "another" })).hash).toBeDefined();
	});

	it("signs statements of a creation and a possession, each with its nonce", async () => {
		const w = await world();
		const { screen } = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen,
			by: "s",
		});
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen,
			by: "s",
		});
		if (c.kind !== "issued" || p.kind !== "issued") throw new Error("refused");
		expect(payloadOf(c.statement)).toMatchObject({ purpose: "creation", creation: creationItems });
		expect(payloadOf(p.statement)).toMatchObject({
			purpose: "possession",
			possession: possessionItems,
		});
		expect(typeof payloadOf(c.statement).nonce).toBe("string");
	});
});

async function askOf(): Promise<IssueAsk> {
	return { purpose: "authorization", items, screen: screenKeys().screen, by: "src" };
}

const refusal = (reason: RegExp) => ({
	refusals: [
		expect.objectContaining({ where: "approvals", reason: expect.stringMatching(reason) }),
	],
});

describe("declaring the items", () => {
	const declaring = (name: string, names: readonly string[]) =>
		defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
			m.contribute(statementItems).by(() => ({ purpose: "authorization", names, by: name })),
		]);

	it("refuses boot for a name no schema holds", async () => {
		await expect(world({ items: declaring("odd", ["amount"]) })).rejects.toMatchObject(
			refusal(/fills authorization\/amount/),
		);
	});

	it("refuses boot for an item two modules fill", async () => {
		await expect(world({ modules: [declaring("second", ["scope"])] })).rejects.toMatchObject(
			refusal(/both fill authorization\/scope/),
		);
	});
});

describe("using a statement", () => {
	it("approves by an assertion over its challenge, once; the same assertion again answers alike", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const t = await issued(w);
		const assertion = w.assert(t.challenge);
		const used = await w.approvals.use({ statement: t.statement, assertion });
		expect(used).toEqual({
			kind: "approved",
			approval: {
				hash: t.hash,
				purpose: "authorization",
				items,
				subject: "s1",
				credential: key.id,
				usedAt: 1_800_000_000_000,
			},
		});
		expect(await w.approvals.use({ statement: t.statement, assertion })).toEqual(used);
		const other = w.assert(t.challenge);
		expect(await w.approvals.use({ statement: t.statement, assertion: other })).toEqual({
			kind: "refused",
			reason: "used",
		});
		expect(await w.approvals.usedOf(t.hash)).toEqual(used.kind === "approved" && used.approval);
	});

	it("approves one of two assertions given at once, and refuses the other", async () => {
		const w = await world();
		await w.plant("s1");
		const t = await issued(w);
		const answers = await Promise.all([
			w.approvals.use({ statement: t.statement, assertion: w.assert(t.challenge) }),
			w.approvals.use({ statement: t.statement, assertion: w.assert(t.challenge) }),
		]);
		expect(answers.map((a) => a.kind).sort()).toEqual(["approved", "refused"]);
	});

	it("refuses an assertion over another challenge, a statement not issued here, and one expired", async () => {
		const w = await world();
		await w.plant("s1");
		const t = await issued(w);
		const elsewhere = w.assert(sha256("other"));
		expect(await w.approvals.use({ statement: t.statement, assertion: elsewhere })).toMatchObject({
			kind: "refused",
		});
		expect(await w.approvals.usedOf(t.hash)).toBeUndefined();
		const forged = `${t.statement}x`;
		expect(await w.approvals.use({ statement: forged, assertion: w.assert(t.challenge) })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		w.advance(5 * 60_000 + 1);
		expect(
			await w.approvals.use({ statement: t.statement, assertion: w.assert(t.challenge) }),
		).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});

	it("refuses an assertion whose user was not verified, whatever passkeys' section lets through", async () => {
		const w = await world({ passkeys: { "user-verification": "preferred" } });
		await w.plant("s1");
		const t = await issued(w);
		const unverified = w.assert(t.challenge, (f) => f & ~0x04);
		expect(await w.approvals.use({ statement: t.statement, assertion: unverified })).toEqual({
			kind: "refused",
			reason: "unverified",
		});
	});

	it("uses a possession by its pending key's verification, and no other purpose so", async () => {
		const w = await world();
		const { screen } = screenKeys();
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen,
			by: "s",
		});
		if (p.kind !== "issued") throw new Error(p.reason);
		const used = await w.approvals.use({ statement: p.statement, verification: "v1" });
		expect(used).toMatchObject({ kind: "approved", approval: { verification: "v1" } });
		expect(await w.approvals.use({ statement: p.statement, verification: "v1" })).toEqual(used);
		expect(await w.approvals.use({ statement: p.statement, verification: "v2" })).toEqual({
			kind: "refused",
			reason: "used",
		});
		const t = await issued(w);
		expect(await w.approvals.use({ statement: t.statement, verification: "v1" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
	});
});

describe("a continuation", () => {
	it("takes each next sequence number the screen signed, runs its step once and answers what it kept", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		expect(c.challenge).toBe(sha256(challengeInput(c.statement, "create")));
		let runs = 0;
		const step = (seq: number, body: string, signature?: string) =>
			w.approvals.continue({
				hash: c.hash,
				seq,
				body,
				signature: signature ?? keys.signs(continuationInput(c.hash, seq, sha256(body))),
				step: async () => {
					runs += 1;
					return { reserved: `${body}-${runs}` };
				},
			});
		expect(await step(1, "b1")).toEqual({
			kind: "continued",
			seq: 1,
			again: false,
			result: { reserved: "b1-1" },
		});
		expect(await step(1, "b1")).toEqual({
			kind: "continued",
			seq: 1,
			again: true,
			result: { reserved: "b1-1" },
		});
		expect(runs).toBe(1);
		expect(await step(1, "b2")).toEqual({ kind: "refused", reason: "seq" });
		expect(await step(3, "b3")).toEqual({ kind: "refused", reason: "seq" });
		const other = screenKeys().signs(continuationInput(c.hash, 2, sha256("b2")));
		expect(await step(2, "b2", other)).toEqual({ kind: "refused", reason: "signature" });
		expect(await step(2, "b2")).toMatchObject({
			kind: "continued",
			seq: 2,
			result: { reserved: "b2-2" },
		});
		const t = await issued(w);
		expect(
			await w.approvals.continue({
				hash: t.hash,
				seq: 1,
				body: "b",
				signature: "s",
				step: async () => null,
			}),
		).toEqual({ kind: "refused", reason: "purpose" });
	});

	it("runs a step once for two calls at once, and again only once the call that held it let go", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const signature = keys.signs(continuationInput(c.hash, 1, sha256("b1")));
		let release = () => {};
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		let runs = 0;
		const call = (step: () => Promise<string>) =>
			w.approvals.continue({ hash: c.hash, seq: 1, body: "b1", signature, step });
		const first = call(async () => {
			runs += 1;
			await held;
			throw new Error("lost");
		});
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(await call(async () => "second")).toEqual({ kind: "refused", reason: "pending" });
		const next = keys.signs(continuationInput(c.hash, 2, sha256("b2")));
		const two = await w.approvals.continue({
			hash: c.hash,
			seq: 2,
			body: "b2",
			signature: next,
			step: async () => 2,
		});
		expect(two).toEqual({ kind: "refused", reason: "seq" });
		release();
		await expect(first).rejects.toThrow("lost");
		expect(runs).toBe(1);
		expect(await call(async () => "again")).toEqual({ kind: "refused", reason: "pending" });
		w.advance(30_001);
		expect(await call(async () => "again")).toEqual({
			kind: "continued",
			seq: 1,
			again: true,
			result: "again",
		});
	});
});

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
		const jws = openSealed(keys.encKey, done, hpke.info.completion, t.hash);
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
		expect(openSealed(keys.encKey, done, hpke.info.completion, t.hash)).toBeDefined();
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
