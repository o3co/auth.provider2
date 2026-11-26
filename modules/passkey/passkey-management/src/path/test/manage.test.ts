import { takenOverAfterMs } from "@mod/approvals/testing";
import { allowed, effectOf, emptyState, type FlowState, fold } from "@mod/authority-rules";
import { continuations } from "@mod/continuation-wire";
import { challengeInput, hpke } from "@mod/sdk-core-wire";
import type { Stage } from "@mod/transparency";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import {
	b64,
	opened,
	payloadOf,
	register,
	rulesOf,
	screen,
	sha256,
	withFirstKey,
} from "./world.ts";

type Started = Awaited<ReturnType<typeof withFirstKey>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const utf8 = (text: string) => new TextEncoder().encode(text);

/** A passkey-manage approved by one of alice's keys, her first unless told, and the list its finish answers, opened. */
async function approved(
	k: Started,
	by: { auth: Started["auth"]; id: string } = { ...k, id: k.key.id },
) {
	const s = await screen();
	const started = await k.w.post("/approval/start", {
		purpose: "passkey-manage",
		eEnc: s.eEnc,
		eSigX: s.eSigX,
		eSigY: s.eSigY,
	});
	const statement = started.json.statement as string;
	const request = k.cer.request(sha256(challengeInput(statement, "get")), [], "required");
	const assertion = JSON.stringify(
		by.auth.get(request as never, { origin: testOrigin }, {}, by.id),
	);
	const finished = await k.w.post("/approval/finish", { statement, assertion });
	expect(finished.status).toBe(200);
	return {
		s,
		statement,
		hash: sha256(statement),
		assertion,
		list: await read(s, sha256(statement), finished.json),
	};
}

/** A completion the Core answered, opened as the screen opens it: its padded length and its payload. */
async function read(s: Screen, hash: string, json: Record<string, unknown>) {
	const text = await opened(
		s,
		json.sealed as never,
		hpke.info.completion,
		hpke.completionAad("passkey-manage", hash),
	);
	const jws = hpke.unpaddedCompletion(text ?? "");
	if (!jws) throw new Error("not padded to a bucket");
	return { length: (text ?? "").length, payload: payloadOf(jws) };
}

/** A rename sealed by the screen to the Core, signed by its E_sig, as `/continue`'s fields. */
async function renaming(k: Started, s: Screen, statement: string, seq: number, body: unknown) {
	const hash = sha256(statement);
	const bodyHash = sha256(continuations.bodyText("rename", body) as string);
	const sig = s.signs(continuations.of("rename", hash, seq, bodyHash));
	const plain = continuations.plainOf("rename", body, sig) as string;
	const box = await s.seal(
		k.w.corePoint,
		hpke.info.continuation,
		utf8(continuations.aad("rename", hash, seq)),
		utf8(plain),
	);
	return { statement, stage: "rename", seq: String(seq), enc: b64(box.enc), ct: b64(box.ct) };
}

/** A delete sealed by the screen to the Core, signed by its E_sig, as `/continue`'s fields. */
async function deleting(k: Started, s: Screen, statement: string, seq: number, credential: string) {
	const hash = sha256(statement);
	const body = { credential_id: credential };
	const bodyHash = sha256(continuations.bodyText("delete", body) as string);
	const sig = s.signs(continuations.of("delete", hash, seq, bodyHash));
	const plain = continuations.plainOf("delete", body, sig) as string;
	const box = await s.seal(
		k.w.corePoint,
		hpke.info.continuation,
		utf8(continuations.aad("delete", hash, seq)),
		utf8(plain),
	);
	return { statement, stage: "delete", seq: String(seq), enc: b64(box.enc), ct: b64(box.ct) };
}

/** A second key of alice's, added by a passkey-add her first key approves, over the routes; and its authenticator. */
async function added(k: Started) {
	const s = await screen();
	const started = await k.w.post("/approval/start", {
		purpose: "passkey-add",
		eEnc: s.eEnc,
		eSigX: s.eSigX,
		eSigY: s.eSigY,
	});
	const statement = started.json.statement as string;
	const request = k.cer.request(sha256(challengeInput(statement, "get")), [], "required");
	const approval = JSON.stringify(
		k.auth.get(request as never, { origin: testOrigin }, {}, k.key.id),
	);
	const finished = await k.w.post("/approval/finish", { statement, assertion: approval });
	const aad = hpke.completionAad("passkey-add", sha256(statement));
	const done = await opened(s, finished.json.sealed as never, hpke.info.completion, aad);
	const creation = payloadOf(hpke.unpaddedCompletion(done ?? "") ?? "").creation as string;
	const auth = softwareAuthenticator();
	const r = await register(k.w, s, creation, auth);
	expect(
		(await k.w.post("/key/finish", { statement: r.possession, assertion: r.assertion })).status,
	).toBe(200);
	return { id: r.key.id, auth };
}

const keysOf = (k: Started) =>
	(k.w.frames.value({ of: "subject", id: "s1" }, { part: "passkeys", name: "keys" }) as FlowState)
		.keys;

describe("a key deleted by a passkey-manage, from the approval to the log, over real sealing", () => {
	it("deletes the key named, its record allowed by the rules, its removal told, and answers its key change at the list's length", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		expect(m.list.payload.keys).toHaveLength(2);
		const before = keysOf(k);
		const fields = await deleting(k, m.s, m.statement, 1, second.id);
		const answered = await k.w.post("/continue", fields);
		expect(answered.status).toBe(200);
		const change = await read(m.s, m.hash, answered.json);
		expect(change.length).toBe(m.list.length);
		expect(change.payload).toMatchObject({
			purpose: "passkey-manage",
			change: { op: "delete", credential_id: second.id },
			receipt: expect.any(String),
		});
		// The key named alone is gone, its removal told once; alice's first key stays.
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([k.key.id]);
		expect(k.w.told).toEqual([["s1", second.id, false]]);
		// Its record, read by the rules as a monitor reads it, against the state before it.
		const stage = k.w.book.sent.at(-1)?.stage as Stage;
		const ask = (await rulesOf(k.w))(stage, { ...emptyState, keys: before });
		expect(allowed(ask)).toEqual({ allowed: true });
		const deleted = Object.entries(before).find(
			([, x]) => x.credential === second.id,
		)?.[0] as string;
		const sid = payloadOf(m.statement).sid as string;
		expect(effectOf(ask)).toEqual({ removeKey: deleted, consume: [`statement:${sid}`] });
		// A family rooted in the key deleted goes with it (DelDrop), so its refresh is refused on the log.
		const family = { chain: [deleted], position: 9, acceptedAt: 0, approval: "a" };
		const rooted = {
			...emptyState,
			keys: before,
			families: { f1: family },
		} as unknown as FlowState;
		const envelope = {
			id: "x",
			kind: "keyChange",
			op: stage.op,
			stage: 1,
			last: true,
			position: 10,
			acceptedAt: 0,
		} as const;
		const after = fold(rooted, envelope, effectOf(ask), { verdict: "verified", outcome: "took" });
		expect(after.families).toEqual({});
		expect(Object.keys(after.keys)).toEqual(Object.keys(before).filter((id) => id !== deleted));
		// The same continuation again: the answer kept, alike; one record on the log.
		const records = k.w.book.records({ of: "subject", id: "s1" }).length;
		expect((await k.w.post("/continue", fields)).json).toEqual(answered.json);
		expect(k.w.book.records({ of: "subject", id: "s1" })).toHaveLength(records);
		await k.w.app.stop();
	});

	it("answers a delete not taken by the list naming why, at the same length, and that answer alone for its number", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		// Alice's one key: the last is never deleted.
		const fields = await deleting(k, m.s, m.statement, 1, k.key.id);
		const answered = await k.w.post("/continue", fields);
		expect(answered.status).toBe(200);
		const list = await read(m.s, m.hash, answered.json);
		expect(list.length).toBe(m.list.length);
		expect(list.payload).toMatchObject({
			keys: [{ credential_id: k.key.id }],
			continued: { stage: "delete", seq: 1, refused: "last" },
		});
		// Its number answered once: a second key added since changes nothing for it.
		await added(k);
		expect((await k.w.post("/continue", fields)).json).toEqual(answered.json);
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toContain(k.key.id);
		await k.w.app.stop();
	});

	it("deletes one key from one passkey-manage, and none it does not hold, answering the list why", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const third = await added(k);
		const m = await approved(k);
		// A key none of alice's: not taken, the list unchanged.
		const none = await k.w.post("/continue", await deleting(k, m.s, m.statement, 1, "AQIDBA"));
		expect((await read(m.s, m.hash, none.json)).payload).toMatchObject({
			continued: { stage: "delete", seq: 1, refused: "unknown" },
		});
		await k.w.post("/continue", await deleting(k, m.s, m.statement, 2, second.id));
		// Its mark used: a second deletion under it is not taken, though a key would be left.
		const twice = await k.w.post("/continue", await deleting(k, m.s, m.statement, 3, third.id));
		const list = await read(m.s, m.hash, twice.json);
		expect(list.payload).toMatchObject({ continued: { stage: "delete", seq: 3, refused: "used" } });
		expect(list.payload.keys.map((r: { credential_id: string }) => r.credential_id)).toContain(
			third.id,
		);
		await k.w.app.stop();
	});

	it("deletes the approving key itself, and refuses the passkey-manage's later steps", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		const answered = await k.w.post("/continue", await deleting(k, m.s, m.statement, 1, k.key.id));
		expect((await read(m.s, m.hash, answered.json)).payload).toMatchObject({
			change: { op: "delete", credential_id: k.key.id },
		});
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([second.id]);
		const rename = await renaming(k, m.s, m.statement, 2, { credential_id: second.id, label: "x" });
		expect((await k.w.post("/continue", rename)).json).toEqual({ error: "access_denied" });
		await k.w.app.stop();
	});

	it("takes in a deletion placed and judged late when it is asked again, answering its first receipt", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		const flow = { of: "subject", id: "s1" } as const;
		const fields = await deleting(k, m.s, m.statement, 1, second.id);
		// Placed, its judgment still to come: the first run gives up waiting for it, keeping nothing.
		k.w.book.judgeOnAppend(undefined);
		await expect(k.w.post("/continue", fields)).rejects.toThrow(/unavailable/);
		const position = k.w.book.records(flow).length;
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toContain(second.id);
		// Judged since; asked again past the first run's hold, nobody having taken it in.
		k.w.book.judge(flow, position, { verdict: "verified", outcome: "took" });
		k.w.advance(takenOverAfterMs + 1);
		const again = await k.w.post("/continue", fields);
		expect(again.status).toBe(200);
		expect((await read(m.s, m.hash, again.json)).payload).toMatchObject({
			change: { op: "delete", credential_id: second.id },
		});
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([k.key.id]);
		expect(k.w.told).toEqual([["s1", second.id, false]]);
		expect(k.w.book.records(flow)).toHaveLength(position);
		await k.w.app.stop();
	});

	it("answers a deletion placed that did not take with a word of its own, never its receipt", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		const flow = { of: "subject", id: "s1" } as const;
		k.w.book.judgeOnAppend({ verdict: "verified", outcome: "didNotTake" });
		const answered = await k.w.post("/continue", await deleting(k, m.s, m.statement, 1, second.id));
		expect(answered.json).toEqual({ error: "access_denied" });
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toContain(second.id);
		expect(k.w.book.records(flow).length).toBeGreaterThan(0);
		await k.w.app.stop();
	});

	it("completes a self-delete whose answer was lost, though its approving key is gone", async () => {
		const k = await withFirstKey();
		await added(k);
		const m = await approved(k);
		const fields = await deleting(k, m.s, m.statement, 1, k.key.id);
		k.w.statements.fallAfter(m.hash, 1);
		await expect(k.w.post("/continue", fields)).rejects.toThrow("fell");
		k.w.advance(takenOverAfterMs + 1);
		const again = await k.w.post("/continue", fields);
		expect(again.status).toBe(200);
		expect((await read(m.s, m.hash, again.json)).payload).toMatchObject({
			change: { op: "delete", credential_id: k.key.id },
		});
		await k.w.app.stop();
	});

	it("completes a delete placed whose answer was lost, run again once its hold lapsed, with its first receipt", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		const fields = await deleting(k, m.s, m.statement, 1, second.id);
		// The step placed the deletion, then its answer's keeping fell.
		k.w.statements.fallAfter(m.hash, 1);
		await expect(k.w.post("/continue", fields)).rejects.toThrow("fell");
		const flow = { of: "subject", id: "s1" } as const;
		const placed = k.w.book.records(flow).length;
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([k.key.id]);
		k.w.advance(takenOverAfterMs + 1);
		const again = await k.w.post("/continue", fields);
		expect(again.status).toBe(200);
		expect((await read(m.s, m.hash, again.json)).payload).toMatchObject({
			change: { op: "delete", credential_id: second.id },
		});
		expect(k.w.book.records(flow)).toHaveLength(placed);
		await k.w.app.stop();
	});
});

describe("a key deleted, at its edges", () => {
	it("answers `last` exactly where the rules refuse the same deletion, and takes it where they allow it", async () => {
		const k = await withFirstKey();
		const alone = { ...emptyState, keys: keysOf(k) } as FlowState;
		const m = await approved(k);
		const last = await k.w.post("/continue", await deleting(k, m.s, m.statement, 1, k.key.id));
		expect((await read(m.s, m.hash, last.json)).payload).toMatchObject({
			continued: { stage: "delete", refused: "last" },
		});
		await added(k);
		const both = { ...emptyState, keys: keysOf(k) } as FlowState;
		// The same deletion, by the same key, once another is live.
		const n = await approved(k);
		const taken = await k.w.post("/continue", await deleting(k, n.s, n.statement, 1, k.key.id));
		expect((await read(n.s, n.hash, taken.json)).payload).toMatchObject({
			change: { op: "delete", credential_id: k.key.id },
		});
		const stage = k.w.book.sent.at(-1)?.stage as Stage;
		const askOf = await rulesOf(k.w);
		expect(allowed(askOf(stage, both))).toEqual({ allowed: true });
		expect(allowed(askOf(stage, alone))).toEqual({
			allowed: false,
			reason: "the flow's last key is not deleted: a reset, a denial or an erasure takes it",
		});
		await k.w.app.stop();
	});

	it.each([
		["first", [0, 1]],
		["second", [1, 0]],
	])(
		"takes one of two self-deletes racing, the %s sent first, the other answered `last`",
		async (_, order) => {
			const k = await withFirstKey();
			const second = await added(k);
			const by = [{ ...k, id: k.key.id }, second];
			const approvals = [await approved(k, by[0]), await approved(k, by[1])];
			const fields = await Promise.all(
				approvals.map((m, i) => deleting(k, m.s, m.statement, 1, by[i]?.id as string)),
			);
			// Both sealed before either is posted; the posts then run together.
			const posted: Promise<Awaited<ReturnType<typeof k.w.post>>>[] = [];
			for (const i of order) posted[i] = k.w.post("/continue", fields[i] ?? {});
			// Answered in the approvals' order, whichever was sent first.
			const answered = await Promise.all(posted);
			expect(answered.map((x) => x?.status)).toEqual([200, 200]);
			const answers = await Promise.all(
				approvals.map(async (m, i) => (await read(m.s, m.hash, answered[i]?.json ?? {})).payload),
			);
			const outcomes = answers.map((x) => x.change?.op ?? x.continued?.refused);
			expect([...outcomes].sort()).toEqual(["delete", "last"]);
			// The key left is the one whose deletion was answered `last`.
			const loser = outcomes.indexOf("last");
			expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([by[loser]?.id]);
			await k.w.app.stop();
		},
	);

	it("keeps nothing where telling the removal failed after the deletion took, and tells it on the retry", async () => {
		const k = await withFirstKey();
		const second = await added(k);
		const m = await approved(k);
		const fields = await deleting(k, m.s, m.statement, 1, second.id);
		k.w.failRemovalOnce();
		await expect(k.w.post("/continue", fields)).rejects.toThrow(/unavailable/);
		const flow = { of: "subject", id: "s1" } as const;
		const placed = k.w.book.records(flow).length;
		expect(Object.values(keysOf(k)).map((x) => x.credential)).toEqual([k.key.id]);
		expect(k.w.told).toEqual([]);
		k.w.advance(takenOverAfterMs + 1);
		const again = await k.w.post("/continue", fields);
		const answer = (await read(m.s, m.hash, again.json)).payload;
		expect(answer).toMatchObject({
			change: { op: "delete", credential_id: second.id },
			receipt: expect.any(String),
		});
		expect(k.w.told).toEqual([["s1", second.id, false]]);
		// The one record placed before: the retry answers it, the next post the same, and tells nothing again.
		expect(k.w.book.records(flow)).toHaveLength(placed);
		const third = await k.w.post("/continue", fields);
		expect((await read(m.s, m.hash, third.json)).payload).toEqual(answer);
		expect(k.w.told).toHaveLength(1);
		await k.w.app.stop();
	});
});

describe("a person's keys listed and one renamed, from the approval to the list again, over real sealing", () => {
	it("lists alice's key, renames it, and answers the list again alike, each answer one length", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		expect(m.list.length).toBe(hpke.completionBuckets[0]);
		expect(m.list.payload).toMatchObject({
			purpose: "passkey-manage",
			t_hash: m.hash,
			assertion_hash: sha256(m.assertion),
			keys: [
				{ credential_id: k.key.id, label: expect.stringMatching(/^Passkey \d{4}-\d{2}-\d{2}$/) },
			],
		});
		const body = { credential_id: k.key.id, label: "Alice's laptop 💻" };
		const fields = await renaming(k, m.s, m.statement, 1, body);
		const answered = await k.w.post("/continue", fields);
		expect(answered.status).toBe(200);
		const after = await read(m.s, m.hash, answered.json);
		expect(after.length).toBe(m.list.length);
		expect(after.payload).toMatchObject({
			keys: [{ credential_id: k.key.id, label: "Alice's laptop 💻" }],
			continued: {
				stage: "rename",
				seq: 1,
				body_hash: sha256(continuations.bodyText("rename", body) as string),
			},
		});
		// The same continuation again: the answer kept, alike.
		expect((await k.w.post("/continue", fields)).json).toEqual(answered.json);
		// The same number with another body: refused, nothing renamed.
		const other = await renaming(k, m.s, m.statement, 1, { ...body, label: "x" });
		expect((await k.w.post("/continue", other)).json).toEqual({ error: "access_denied" });
		// A key none of alice's: the list unchanged, under the next number.
		const unknown = await renaming(k, m.s, m.statement, 2, { credential_id: "AQIDBA", label: "y" });
		const unchanged = await read(m.s, m.hash, (await k.w.post("/continue", unknown)).json);
		expect(unchanged.payload.keys).toEqual(after.payload.keys);
		expect(unchanged.payload.continued).toMatchObject({ seq: 2 });
	});

	it("runs a rename whose answer was lost again once its hold lapsed, answering alike from then on", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		const fields = await renaming(k, m.s, m.statement, 1, {
			credential_id: k.key.id,
			label: "laptop",
		});
		// The step renamed the key, then fell before its answer was kept.
		k.w.statements.fallAfter(m.hash, 1);
		await expect(k.w.post("/continue", fields)).rejects.toThrow("fell");
		// Meanwhile the same continuation is held: asked again later.
		expect((await k.w.post("/continue", fields)).status).not.toBe(200);
		k.w.advance(takenOverAfterMs + 1);
		const again = await k.w.post("/continue", fields);
		expect(again.status).toBe(200);
		const read1 = await read(m.s, m.hash, again.json);
		expect(read1.payload.keys).toMatchObject([{ credential_id: k.key.id, label: "laptop" }]);
		expect((await k.w.post("/continue", fields)).json).toEqual(again.json);
		// The list as a new approval reads it: the label once, as given.
		expect((await approved(k)).list.payload.keys).toMatchObject([{ label: "laptop" }]);
	});

	it("refuses a rename sealed for another statement, or not sealed to the Core, as access_denied, writing nothing", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		const second = await approved(k);
		const body = { credential_id: k.key.id, label: "x" };
		// Sealed for the second statement, sent with the first.
		const elsewhere = await renaming(k, m.s, second.statement, 1, body);
		expect((await k.w.post("/continue", { ...elsewhere, statement: m.statement })).json).toEqual({
			error: "access_denied",
		});
		const again = await approved(k);
		expect(again.list.payload.keys).toEqual(m.list.payload.keys);
	});
});
