import { createHash } from "node:crypto";
import type { Flow } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { keyChangePart } from "../../contract.ts";
import { type AddedKey, type DeletedKey, keyChangesOver } from "../key-change.ts";
import { keyFlow } from "./flow.ts";

type Flowing = Awaited<ReturnType<typeof keyFlow>>;
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const flow: Flow = { of: "subject", id: "s1" };
const keysRecord = { part: "passkeys", name: "keys" };

function writer(w: Flowing, now = () => 0) {
	const settled: string[] = [];
	const over = keyChangesOver({
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
		now,
	});
	return { ...over, settled };
}

/** `s1` holding two keys, the second approved by the first; and a deletion of `credential` approved by `by`. */
async function twoKeys() {
	const w = await keyFlow();
	w.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
	const { change } = writer(w);
	const first = await w.verified("s1");
	await change(first);
	const registrationOf = async (credential: string) =>
		(await w.passkeys.publicKeyOf(credential))?.registration as string;
	const r1 = await registrationOf(first.credential);
	const k: AddedKey = {
		...(await w.verified("s1", false)),
		approved: {
			statement: "add.jws",
			assertion: '{"id":"k1"}',
			credential: first.credential,
			registration: r1,
			mark: "statement:add",
			generation: 0,
		},
	};
	await change(k);
	const r2 = await registrationOf(k.credential);
	const deleting = (
		credential: string,
		by: { credential: string; registration: string },
	): DeletedKey => ({
		subject: "s1",
		credential,
		op: `rm-${credential}`,
		approval: {
			statement: "manage.jws",
			assertion: '{"id":"approver"}',
			credential: by.credential,
			registration: by.registration,
			mark: "statement:manage",
		},
		continuation: { seq: 1, body: `{"credential_id":"${credential}"}`, signature: "c2ln" },
		until: 1_000,
		heldUntil: 1_000,
	});
	return { w, first, second: k, r1, r2, deleting };
}

const keysOf = (w: Flowing) =>
	Object.keys((w.frames.value(flow, keysRecord) as { keys: Record<string, unknown> }).keys);

describe("a key deleted's change", () => {
	it("is placed with its passkey-manage, its assertion and its continuation, the key named alone dropped", async () => {
		const { w, first, second, r1, r2, deleting } = await twoKeys();
		const { remove, removed, settled } = writer(w);
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		expect(await remove(d)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		expect(w.book.sent.at(-1)?.stage).toMatchObject({
			kind: "keyChange",
			op: d.op,
			keyChange: { statement: sha256("manage.jws"), evidence: sha256(d.continuation.body) },
			preimage: {
				v: 1,
				parent: r2,
				evidence: [
					{ form: "statement", value: "manage.jws" },
					{ form: "assertion", value: '{"id":"approver"}' },
					{
						form: "continuation",
						value: `{"body":${JSON.stringify(d.continuation.body)},"seq":1,"signature":"c2ln"}`,
					},
				],
				content: { variant: "delete", credential: first.credential },
			},
		});
		// The first key goes; the key it approved stays (DelDrop).
		expect(keysOf(w)).toEqual([r2]);
		expect(keysOf(w)).not.toContain(r1);
		expect(settled).toContain("s1");
		// Asked again of the log: this continuation's deletion took, with its receipt; another op's, none.
		expect(await removed(d)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		expect(await removed({ ...d, op: "other" })).toEqual({ kind: "none" });
		// Decided again under its op: ended, nothing more placed.
		const sent = w.book.sent.length;
		expect(await remove(d)).toEqual({ kind: "ended" });
		expect(w.book.sent).toHaveLength(sent);
	});

	it("answers a deletion applied as taken, though a later record on its flow waits for its judgment", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const { remove, removed, change } = writer(w);
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		expect(await remove(d)).toMatchObject({ kind: "took" });
		// Another key change placed after it, its judgment still to come.
		w.book.judgeOnAppend(undefined);
		await expect(change(await w.verified("s1", false))).rejects.toThrow();
		expect(await removed(d)).toEqual({ kind: "took", receipts: ["h.p.s"] });
	});

	it("is placed by another replica's tend where its writer fell after deciding, and answered from the log", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		// Decided, its stage kept beside its op, then the writer gone before it sent.
		const gone = writer({
			...w,
			transparency: {
				...w.transparency,
				send: async () => {
					throw new Error("gone");
				},
			},
		});
		await expect(gone.remove(d)).rejects.toThrow("gone");
		expect(await writer(w).removed(d)).toEqual({ kind: "none" });
		// Past the 5s lease the store's clock holds, the other replica takes it over and resends the stage it kept.
		w.advance(6_000);
		const w2 = await w.replica("w2");
		const placed = w.book.sent.length;
		expect(await w2.tend(flow)).toMatchObject({ did: "tookOver", answer: { result: "accepted" } });
		expect(w.book.sent.slice(placed).map((x) => x.instance)).toEqual(["w2"]);
		expect(await w2.tend(flow)).toEqual({ stepped: 1 });
		expect(keysOf(w)).toEqual([r2]);
		const after = writer(w);
		expect(await after.removed(d)).toEqual({ kind: "took", receipts: ["h.p.s"] });
		expect(after.settled).toEqual(["s1"]);
	});

	it("waits on a non-take a live owner on another replica holds, then answers it, settling nothing", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		w.book.judgeOnAppend({ verdict: "verified", outcome: "didNotTake" });
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		// Sent, then its writer gone before taking it in: its intent pending, its lease live.
		const stalled = writer({
			...w,
			transparency: {
				...w.transparency,
				step: async () => {
					throw new Error("gone");
				},
			},
		});
		await expect(stalled.remove(d)).rejects.toThrow("gone");
		const elsewhere = writer({ ...w, transparency: await w.replica("w2") });
		await expect(elsewhere.removed(d)).rejects.toThrow(/unavailable/);
		// Past the lease, any replica takes it in and answers it.
		w.advance(6_000);
		expect(await elsewhere.removed(d)).toEqual({ kind: "didNotTake" });
		expect(elsewhere.settled).toEqual([]);
	});

	it("answers a deletion taken though its key is held again since, as the flow applied it", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		expect(await writer(w).remove(d)).toMatchObject({ kind: "took" });
		// The same credential held again under another registration: no look at the key is asked.
		const held = w.frames.value(flow, keysRecord) as { keys: Record<string, object> };
		const kept = held.keys[r2] as object;
		w.frames.put(flow, keysRecord, {
			...held,
			keys: { ...held.keys, again: { ...kept, credential: first.credential } },
		} as never);
		expect(await writer(w).removed(d)).toEqual({ kind: "took", receipts: ["h.p.s"] });
	});

	it("is refused expired, nothing placed, where a later call marked its op past expiry while its write was on its way", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		const sent = w.book.sent.length;
		// A decided in time; before its write commits, B, past the expiry, marks the op.
		let b: unknown;
		w.frames.beforeWrite(async () => {
			b = await writer(w, () => 1_001).remove(d);
		});
		expect(await writer(w, () => 900).remove(d)).toEqual({ kind: "refused", reason: "expired" });
		expect(b).toEqual({ kind: "refused", reason: "expired" });
		expect(w.book.sent).toHaveLength(sent);
		expect(keysOf(w)).toHaveLength(2);
	});

	it("keeps no expired where its op ended before the mark: decided again, it is ended", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		// B read past the expiry; before its mark commits, A, in time, places and takes its deletion.
		let a: unknown;
		w.frames.beforeWrite(async () => {
			a = await writer(w, () => 900).remove(d);
		});
		expect(await writer(w, () => 1_001).remove(d)).toEqual({ kind: "ended" });
		expect(a).toMatchObject({ kind: "took" });
		expect(keysOf(w)).toEqual([r2]);
		expect(await writer(w, () => 1_001).removed(d)).toMatchObject({ kind: "took" });
	});

	/** The world with one of its transparency's members answered otherwise. */
	const replacing = (w: Flowing, over: Partial<Flowing["transparency"]>): Flowing => ({
		...w,
		transparency: { ...w.transparency, ...over },
	});
	const markRecord = { part: keyChangePart, name: "preimage" };

	it("reads its op's mark before any other word: a marked op is expired, whatever its approver", async () => {
		const { w, first, second, r1, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		expect(await writer(w, () => 1_001).remove(d)).toEqual({ kind: "refused", reason: "expired" });
		const unapproved = { ...d, approval: { ...d.approval, registration: r1 } };
		expect(await writer(w, () => 900).remove(unapproved)).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});

	it("throws, keeping no clock's expired, where its mark's write fails; a mark it committed is read again", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		// Failing before it commits: nothing kept, and a call in time takes.
		const before = replacing(w, {
			changeHeld: async () => {
				throw new Error("unavailable before");
			},
		});
		await expect(writer(before, () => 1_001).remove(d)).rejects.toThrow("unavailable before");
		const other = { ...d, op: "rm-other" };
		// Failing after it commits: thrown, and the next call, in time or not, reads the mark.
		const after = replacing(w, {
			changeHeld: async (q) => {
				await w.transparency.changeHeld(q);
				throw new Error("unavailable after");
			},
		});
		await expect(writer(after, () => 1_001).remove(other)).rejects.toThrow("unavailable after");
		expect(w.frames.value(flow, markRecord)).toEqual({ expired: other.op });
		expect(await writer(w, () => 900).remove(other)).toEqual({
			kind: "refused",
			reason: "expired",
		});
		expect(await writer(w, () => 900).remove(d)).toMatchObject({ kind: "took" });
	});

	it("answers ended where its op took before its mark committed, the mark left on it harmless", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		let a: unknown;
		const b = replacing(w, {
			changeHeld: async (q) => {
				a = await writer(w, () => 900).remove(d);
				return w.transparency.changeHeld(q);
			},
		});
		expect(await writer(b, () => 1_001).remove(d)).toEqual({ kind: "ended" });
		expect(a).toMatchObject({ kind: "took" });
		expect(w.frames.value(flow, markRecord)).toEqual({ expired: d.op });
		expect(await writer(w, () => 1_001).removed(d)).toMatchObject({ kind: "took" });
	});

	it("protects its op only while its mark stays: another op's mark over it, a call in time decides it anew", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const x = deleting(first.credential, { credential: second.credential, registration: r2 });
		const y = { ...x, op: "rm-y" };
		expect(await writer(w, () => 1_001).remove(x)).toEqual({ kind: "refused", reason: "expired" });
		expect(await writer(w, () => 1_001).remove(y)).toEqual({ kind: "refused", reason: "expired" });
		expect(w.frames.value(flow, markRecord)).toEqual({ expired: y.op });
		// The residual D (approvals' takeover margin) closes: a clock before the expiry reads no mark of x.
		expect(await writer(w, () => 900).remove(x)).toMatchObject({ kind: "took" });
	});

	it("throws, never a clock's expired, where another op's mark takes its place each time", async () => {
		const { w, first, second, r2, deleting } = await twoKeys();
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		const overwritten = replacing(w, {
			changeHeld: async (q) => {
				await w.transparency.changeHeld(q);
				return w.transparency.changeHeld({ ...q, change: () => [{ value: { expired: "rm-y" } }] });
			},
		});
		await expect(writer(overwritten, () => 1_001).remove(d)).rejects.toThrow(/unavailable/);
	});

	it("deletes the approving key itself while another is left", async () => {
		const { w, second, r1, r2, deleting, first } = await twoKeys();
		const { remove } = writer(w);
		const d = deleting(second.credential, { credential: second.credential, registration: r2 });
		expect(await remove(d)).toMatchObject({ kind: "took" });
		expect(keysOf(w)).toEqual([r1]);
		expect(await w.passkeys.publicKeyOf(first.credential)).toBeDefined();
		// Decided again, its approving key gone: the stage placed answers, never `approver`.
		expect(await remove(d)).toEqual({ kind: "ended" });
		expect(await writer(w).removed(d)).toMatchObject({ kind: "took" });
	});

	it("refuses, placing nothing, an approver not as it approved, past expiry, an unknown key, the last", async () => {
		const { w, first, second, r1, r2, deleting } = await twoKeys();
		const sent = w.book.sent.length;
		const d = deleting(first.credential, { credential: second.credential, registration: r2 });
		const { remove } = writer(w);
		expect(await remove({ ...d, approval: { ...d.approval, registration: r1 } })).toEqual({
			kind: "refused",
			reason: "approver",
		});
		// Past its expiry: marked so, an op every later decision of refuses alike, whatever its clock.
		const late = { ...d, op: "rm-late" };
		expect(await writer(w, () => 1_001).remove(late)).toEqual({
			kind: "refused",
			reason: "expired",
		});
		expect(await remove(late)).toEqual({ kind: "refused", reason: "expired" });
		// Past its call's hold: decided by none, thrown, so nothing is kept for its number.
		await expect(writer(w, () => 900).remove({ ...d, heldUntil: 899 })).rejects.toThrow();
		expect(await remove({ ...d, credential: "none", op: "rm-none" })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		expect(w.book.sent).toHaveLength(sent);
		// One key left after a deletion: the last is refused.
		expect(await remove(d)).toMatchObject({ kind: "took" });
		const last = deleting(second.credential, { credential: second.credential, registration: r2 });
		expect(
			await remove({ ...last, approval: { ...last.approval, mark: "statement:other" } }),
		).toEqual({
			kind: "refused",
			reason: "last",
		});
	});
});
