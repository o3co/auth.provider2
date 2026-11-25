import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Flow } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { keyChangePart } from "../../contract.ts";
import { type AddedKey, keyChangesOver } from "../key-change.ts";
import { keyFlow } from "./flow.ts";

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const preimageRecord = { part: keyChangePart, name: "preimage" };
const reservationRecord = { part: "passkeys", name: "reservation" };

async function writer(w: Awaited<ReturnType<typeof keyFlow>>) {
	const settled: string[] = [];
	const { change, receipts } = keyChangesOver({
		registrations: w.regs,
		transparency: w.transparency,
		passkeys: {
			settle: async (subject) => {
				settled.push(subject);
				return w.passkeys.settle(subject);
			},
		},
		digest: w.log.digest,
		pause: async () => {},
		looks: 3,
	});
	return { change, receipts, settled };
}

describe("a first key's change", () => {
	it("is decided, sent with its preimage, taken in as took, and the subject's keys settled", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		const { change, settled } = await writer(w);
		const k = await w.verified("s1");
		expect(await change(k)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		const [sent] = w.book.sent;
		expect(sent?.stage).toMatchObject({
			kind: "keyChange",
			op: k.reservation,
			keyChange: { statement: sha256(k.possession), evidence: sha256(k.assertion) },
			preimage: {
				evidence: [
					{ form: "statement", value: k.creation },
					// The screen's continuation over the creation, in canonical JSON.
					{
						form: "continuation",
						value: '{"body":"{\\"id\\":\\"k\\"}","seq":1,"signature":"c2ln"}',
					},
					{ form: "statement", value: k.possession },
					{ form: "assertion", value: k.assertion },
				],
				content: { variant: "first", credential: k.credential, publicKey: k.publicKey },
			},
		});
		const flow: Flow = { of: "subject", id: "s1" };
		expect(w.frames.value(flow, reservationRecord)).toMatchObject({ state: "active" });
		// The writer's record goes at the op's end.
		expect(w.frames.value(flow, preimageRecord)).toBeUndefined();
		expect(await w.passkeys.publicKeyOf(k.credential)).toMatchObject({
			subject: "s1",
			publicKey: k.publicKey,
		});
		expect(settled).toEqual(["s1"]);
	});

	it("looks again where taking in its end ran late, never reading that as an end", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		let late = true;
		const { change } = await writer({
			...w,
			transparency: {
				...w.transparency,
				step: async (q) => {
					if (!late) return w.transparency.step(q);
					late = false;
					return { refused: "late" };
				},
			},
		});
		expect(await change(await w.verified("s1"))).toEqual({ kind: "took", receipts: ["h.p.s"] });
	});

	it("keeps its stage beside the reservation until the op ends, for another replica's resend", async () => {
		const w = await keyFlow();
		const { change } = await writer(w);
		const k = await w.verified("s1");
		// Unjudged, the op stays open: no end is taken in within the looks.
		await expect(change(k)).rejects.toThrow(Unavailable);
		const flow: Flow = { of: "subject", id: "s1" };
		expect(w.frames.value(flow, preimageRecord)).toEqual(w.book.sent[0]?.stage);
	});

	it("ends without settling where the monitor holds it, the reservation released", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "held", outcome: "took" });
		const { change, settled } = await writer(w);
		const k = await w.verified("s1");
		expect(await change(k)).toEqual({ kind: "ended" });
		expect(settled).toEqual([]);
		const flow: Flow = { of: "subject", id: "s1" };
		expect(w.frames.value(flow, reservationRecord)).toMatchObject({ state: "ended" });
		expect(await w.passkeys.publicKeyOf(k.credential)).toBeUndefined();
	});

	it("answers passkeys' refusal where its reservation would not commit, sending nothing", async () => {
		const w = await keyFlow();
		const { change } = await writer(w);
		const k = await w.verified("s1");
		expect(await change({ ...k, verification: "other" })).toEqual({
			kind: "refused",
			reason: "verification",
		});
		expect(w.book.sent).toEqual([]);
	});

	it("is decided again where its first stage met another record before it", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		const k = await w.verified("s1");
		const flow: Flow = { of: "subject", id: "s1" };
		let first = true;
		const { change } = await writer({
			...w,
			transparency: {
				...w.transparency,
				send: async (q) => {
					// A monitor's record lands between the decision and the send, once.
					if (first) w.book.monitor(flow, "confirmation", {});
					first = false;
					return w.transparency.send(q);
				},
			},
		});
		expect(await change(k)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		expect(w.book.sent.map((s) => s.prev)).toEqual([0, 1]);
	});

	it("settles a change it takes in as another's end, asked again once the first call fell", async () => {
		const w = await keyFlow();
		const { change, receipts, settled } = await writer(w);
		const k = await w.verified("s1");
		expect(await receipts(k)).toBeUndefined();
		// The first call's change is placed, but no judgment comes within its looks.
		await expect(change(k)).rejects.toThrow(Unavailable);
		const flow: Flow = { of: "subject", id: "s1" };
		w.book.judge(flow, 1, { verdict: "verified", outcome: "took" });
		// Asked again past the first call's lease: its stage is taken in as an orphan's, not its own.
		w.advance(60_000);
		expect(await change(k)).toEqual({ kind: "ended" });
		expect(settled).toContain("s1");
		// Its receipt, asked again of the log with the stage made again alike; none for another change.
		expect(await receipts(k)).toEqual(["h.p.s"]);
		expect(await receipts({ ...k, assertion: "[]" })).toBeUndefined();
		expect(w.book.records(flow)).toHaveLength(1);
		expect(w.frames.value(flow, reservationRecord)).toMatchObject({ state: "active" });
		expect(await w.passkeys.publicKeyOf(k.credential)).toMatchObject({
			subject: "s1",
			publicKey: k.publicKey,
		});
	});

	it("decides again where its decision ran late, and refuses no flow's word as passkeys'", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		let late = true;
		const { change } = await writer({
			...w,
			regs: {
				...w.regs,
				commit: async (q) => {
					if (!late) return w.regs.commit(q);
					late = false;
					return { refused: "late" };
				},
			},
		});
		expect(await change(await w.verified("s1"))).toEqual({ kind: "took", receipts: ["h.p.s"] });
		const sealed = await writer({
			...w,
			regs: { ...w.regs, commit: async () => ({ refused: "sealed" }) },
		});
		await expect(sealed.change(await w.verified("s2"))).rejects.toThrow(Unavailable);
	});

	it("is unavailable where its first stage meets another before it every time", async () => {
		const w = await keyFlow();
		const k = await w.verified("s1");
		const flow: Flow = { of: "subject", id: "s1" };
		const { change } = await writer({
			...w,
			transparency: {
				...w.transparency,
				send: async (q) => {
					w.book.monitor(flow, "confirmation", {});
					return w.transparency.send(q);
				},
			},
		});
		await expect(change(k)).rejects.toThrow(Unavailable);
	});

	it("is unavailable, never none, where the log cannot answer a receipt asked again now", async () => {
		const w = await keyFlow();
		const k = await w.verified("s1");
		const { receipts } = await writer({
			...w,
			transparency: {
				...w.transparency,
				receiptOf: async () => ({ answer: { v: 1, result: "refused", refusal: "temporary" } }),
			},
		});
		await expect(receipts(k)).rejects.toThrow(Unavailable);
	});

	it("settles and ends where its step finds its stage taken in by another already", async () => {
		const w = await keyFlow();
		const { change, settled } = await writer({
			...w,
			transparency: {
				...w.transparency,
				// Another replica took its stage (position 1) in: its own step takes in the next record.
				step: async () => ({ position: 2 }),
			},
		});
		expect(await change(await w.verified("s1"))).toEqual({ kind: "ended" });
		expect(settled).toEqual(["s1"]);
	});

	it("binds its envelope to the possession's and the assertion's digests, as the rules check them", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		const { change } = await writer(w);
		// The same inputs and digests authority-rules' envelope check is tested with.
		const possession =
			"eyJhbGciOiJFUzI1NiIsInR5cCI6ImFwcHJvdmFsK2p3dCJ9.eyJwdXJwb3NlIjoicG9zc2Vzc2lvbiJ9.c2lnbmF0dXJl";
		const assertion = '{"id":"k1","response":{"signature":"c2ln"}}';
		await change({ ...(await w.verified("s1")), possession, assertion });
		expect(w.book.sent[0]?.stage.keyChange).toEqual({
			statement: "p_5wwYfl5sOtQrwnw4MimfuUx4yvVSMF8VDiOT2jKkI",
			evidence: "sEEwzKWW5uZNa96UdjoUwblfaWD0INVCWBR3i4sCKf4",
		});
	});
});

describe("a passkey-add's change", () => {
	/** A first key placed for `s1`, and a second reserved and verified, approved by the first. */
	async function approvedAdd(w: Awaited<ReturnType<typeof keyFlow>>) {
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		const { change } = await writer(w);
		const first = await w.verified("s1");
		await change(first);
		const registration = (await w.passkeys.publicKeyOf(first.credential))?.registration as string;
		const k: AddedKey = {
			...(await w.verified("s1", false)),
			continuation: { seq: 1, body: '{"id":"k2"}', signature: "c2ln" },
			approved: {
				statement: "add.jws",
				assertion: '{"id":"k1"}',
				credential: first.credential,
				registration,
				mark: "statement:sid-1",
				generation: 0,
			},
		};
		return { first, k, registration };
	}

	it("names its approving key as parent, carries the approval and the continuation, and consumes its mark", async () => {
		const w = await keyFlow();
		const { k, registration } = await approvedAdd(w);
		const decided: unknown[] = [];
		const { change } = await writer({
			...w,
			regs: {
				...w.regs,
				commit: (q) =>
					w.regs.commit({
						...q,
						decide: (state, held) => {
							const d = q.decide(state, held);
							decided.push(d);
							return d;
						},
					}),
			},
		});
		expect(await change(k)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		const a = k.approved;
		expect(w.book.sent[1]?.stage).toMatchObject({
			kind: "keyChange",
			// The op is the reservation, as the possession names it.
			op: k.reservation,
			keyChange: { statement: sha256(k.possession), evidence: sha256(k.assertion) },
			preimage: {
				parent: registration,
				evidence: [
					{ form: "statement", value: a?.statement },
					{ form: "assertion", value: a?.assertion },
					{ form: "statement", value: k.creation },
					// Canonical JSON of the three, as the rules read a continuation.
					{
						form: "continuation",
						value: '{"body":"{\\"id\\":\\"k2\\"}","seq":1,"signature":"c2ln"}',
					},
					{ form: "statement", value: k.possession },
					{ form: "assertion", value: k.assertion },
				],
				content: { variant: "add", credential: k.credential, publicKey: k.publicKey },
			},
		});
		expect(decided).toEqual([
			expect.objectContaining({
				eff: {
					key: { credential: k.credential, publicKey: k.publicKey, by: registration },
					consume: ["statement:sid-1"],
				},
			}),
		]);
		expect(await w.passkeys.publicKeyOf(k.credential)).toMatchObject({ subject: "s1" });
	});

	it("refuses, sending nothing, where its approving key is no longer the one that approved", async () => {
		const w = await keyFlow();
		const { k } = await approvedAdd(w);
		const { change } = await writer(w);
		const a = k.approved as NonNullable<AddedKey["approved"]>;
		for (const approved of [
			{ ...a, registration: "r-later" },
			{ ...a, credential: "another" },
		])
			expect(await change({ ...k, approved })).toEqual({ kind: "refused", reason: "approver" });
		expect(w.book.sent).toHaveLength(1);
	});

	it("refuses a second key from one passkey-add, its mark consumed on the flow", async () => {
		const w = await keyFlow();
		const { k } = await approvedAdd(w);
		const { change } = await writer(w);
		const flow: Flow = { of: "subject", id: "s1" };
		w.frames.put(
			flow,
			{ part: "grants", name: "state" },
			{ approvals: {}, consumed: ["statement:sid-1"] },
		);
		expect(await change(k)).toEqual({ kind: "refused", reason: "used" });
		expect(w.book.sent).toHaveLength(1);
	});

	it("refuses a creation of another key generation than the flow's", async () => {
		const w = await keyFlow();
		const { k } = await approvedAdd(w);
		const { change } = await writer(w);
		const a = k.approved as NonNullable<AddedKey["approved"]>;
		expect(await change({ ...k, approved: { ...a, generation: 1 } })).toEqual({
			kind: "refused",
			reason: "fenced",
		});
	});
});

describe("a sign-up's change (F1)", () => {
	it("carries its T before the first key's ceremony, approved by none", async () => {
		const w = await keyFlow();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		const { change } = await writer(w);
		const k = { ...(await w.verified("s1")), signUp: { statement: "t.jws" } };
		expect(await change(k)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		const preimage = w.book.sent[0]?.stage.preimage;
		expect(preimage?.parent).toBeUndefined();
		expect(preimage?.evidence.map((e) => e.form)).toEqual([
			"statement",
			"statement",
			"continuation",
			"statement",
			"assertion",
		]);
		expect(preimage?.evidence[0]).toEqual({ form: "statement", value: "t.jws" });
		expect(preimage?.content).toMatchObject({ variant: "first", credential: k.credential });
	});
});
