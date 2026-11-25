import { keyList } from "@mod/passkeys";
import { hpke, payloads, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { openSealed, screenKeys, sha256, world } from "../../../test/fixtures/world.ts";

type World = Awaited<ReturnType<typeof world>>;
const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));

/** A passkey-manage issued to a screen and used by s1's key. */
async function used(w: World) {
	const key = await w.plant("s1");
	const keys = screenKeys();
	const a = await w.approvals.issue({
		purpose: "passkey-manage",
		items: {},
		screen: keys.screen,
		by: "src",
	});
	if (a.kind !== "issued") throw new Error(a.reason);
	const assertion = w.assert(a.challenge);
	await w.approvals.use({ statement: a.statement, assertion });
	return { a, keys, assertion, key };
}

/** The completion opened as the screen opens it: its length, and its JWS verified and read. */
async function opened(
	w: World,
	keys: ReturnType<typeof screenKeys>,
	hash: string,
	box: { enc: string; ct: string },
) {
	const text = openSealed(
		keys.encKey,
		box,
		hpke.info.completion,
		hpke.completionAad("passkey-manage", hash),
	);
	const jws = hpke.unpaddedCompletion(text) as string;
	expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
	const payload = payloadOf(jws);
	expect(payloads.completions.passkeyManage.safeParse(payload).success).toBe(true);
	return { length: text.length, payload };
}

describe("a passkey-manage's completion", () => {
	it("lists the subject's keys, padded to the smaller bucket, kept and answered alike after", async () => {
		const w = await world();
		const { a, keys, assertion, key } = await used(w);
		const record = w.credentials.kept.get(key.id) as unknown as { details: object };
		w.credentials.kept.set(key.id, {
			...record,
			details: { ...record.details, createdAt: Date.UTC(2026, 10, 25, 12) },
		} as never);
		const done = await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true });
		if (done.kind !== "completed") throw new Error(done.reason);
		const read = await opened(w, keys, a.hash, done);
		expect(read.length).toBe(hpke.completionBuckets[0]);
		expect(read.payload).toMatchObject({
			purpose: "passkey-manage",
			t_hash: a.hash,
			assertion_hash: sha256(assertion),
			keys: [
				{
					credential_id: key.id,
					label: "Passkey 2026-11-25",
					created_at: Date.UTC(2026, 10, 25, 12) / 1000,
				},
			],
		});
		expect(read.payload).not.toHaveProperty("continued");
		// Asked again, past the statement's life, the one kept; by another assertion, none.
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.completePasskeyManage({ hash: a.hash, assertion })).toEqual(done);
		expect(
			await w.approvals.completePasskeyManage({
				hash: a.hash,
				assertion: w.assert(sha256("other")),
			}),
		).toEqual({ kind: "refused", reason: "assertion" });
	});

	it("names a continuation's rename and the label given, and keeps nothing of it", async () => {
		const w = await world();
		const { a, keys, assertion, key } = await used(w);
		await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true });
		// Its continuation number 1 taken, its body's hash kept, unanswered.
		await w.statements.store.change(a.hash, (r) => ({
			value: {
				...(r as object),
				seq: 1,
				body: sha256("b"),
				claimed: { by: "t", until: Number.MAX_SAFE_INTEGER },
			} as never,
		}));
		const before = JSON.stringify(w.statements.value(a.hash));
		const list = w.app.get(keyList);
		const until = Number.MAX_SAFE_INTEGER;
		await list.rename({
			subject: "s1",
			credential: key.id,
			label: "Laptop",
			by: { statement: a.hash, seq: 1, until },
		});
		const continued = { stage: "rename" as const, seq: 1, bodyHash: sha256("b") };
		const done = await w.approvals.completePasskeyManage({ hash: a.hash, continued });
		if (done.kind !== "completed") throw new Error(done.reason);
		const read = await opened(w, keys, a.hash, done);
		expect(read.payload).toMatchObject({
			keys: [{ credential_id: key.id, label: "Laptop", created_at: 0 }],
			continued: { stage: "rename", seq: 1, body_hash: sha256("b") },
		});
		expect(JSON.stringify(w.statements.value(a.hash))).toBe(before);
		// Up to its record's end, not after.
		w.advance(6 * 60_000 - 1000);
		expect(await w.approvals.completePasskeyManage({ hash: a.hash, continued })).toMatchObject({
			kind: "completed",
		});
		// A store that held it past its end (its expiry moved back): still none.
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), exp: (r as unknown as { exp: number }).exp - 2000 } as never,
		}));
		expect(await w.approvals.completePasskeyManage({ hash: a.hash, continued })).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});

	it("pads to the larger bucket where a key's credential ID is longer than 128 bytes", async () => {
		const w = await world();
		const { a, keys, assertion, key } = await used(w);
		const long = Buffer.alloc(200, 9).toString("base64url");
		const flow = { of: "subject", id: "s1" } as const;
		const held = w.frames.value(
			{ of: "subject", id: "s1" },
			{ part: "passkeys", name: "keys" },
		) as { keys: Record<string, { credential: string }> };
		w.frames.put(
			flow,
			{ part: "passkeys", name: "keys" },
			{
				...held,
				keys: { ...held.keys, r1: { ...held.keys.r0, credential: long } },
			},
		);
		w.credentials.kept.set(long, w.credentials.kept.get(key.id) as never);
		const done = await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true });
		if (done.kind !== "completed") throw new Error(done.reason);
		expect((await opened(w, keys, a.hash, done)).length).toBe(hpke.completionBuckets[1]);
	});

	it("refuses one not used, of another purpose, and one used but past expiry with none kept", async () => {
		const w = await world();
		const { a, assertion } = await used(w);
		const keys = screenKeys();
		const fresh = await w.approvals.issue({
			purpose: "passkey-manage",
			items: {},
			screen: keys.screen,
			by: "src",
		});
		const add = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: keys.screen,
			by: "src",
		});
		if (fresh.kind !== "issued" || add.kind !== "issued") throw new Error("not issued");
		expect(await w.approvals.completePasskeyManage({ hash: fresh.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unused",
		});
		expect(await w.approvals.completePasskeyManage({ hash: add.hash, assertion })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		w.advance(5 * 60_000 + 1000);
		expect(
			await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true }),
		).toEqual({ kind: "refused", reason: "expired" });
	});

	it("fits 16 keys of the longest IDs and labels in the larger bucket, and refuses 17 keeping none", async () => {
		const w = await world();
		const { a, keys, assertion, key } = await used(w);
		const flow = { of: "subject", id: "s1" } as const;
		const where = { part: "passkeys", name: "keys" } as const;
		const held = w.frames.value(flow, where) as { keys: Record<string, { credential: string }> };
		const record = w.credentials.kept.get(key.id) as unknown as { details: object };
		const label = "😀".repeat(64);
		const holding = (count: number) => {
			const many: Record<string, object> = {};
			for (let i = 0; i < count; i++) {
				const id = Buffer.alloc(1023, i).toString("base64url");
				many[`r${i}`] = { ...held.keys.r0, credential: id };
				w.credentials.kept.set(id, { ...record, details: { ...record.details, label } } as never);
			}
			w.frames.put(flow, where, { ...held, keys: many } as never);
		};
		holding(17);
		expect(
			await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true }),
		).toEqual({ kind: "refused", reason: "form" });
		expect(w.statements.value(a.hash)).toMatchObject({ state: "used" });
		holding(16);
		const done = await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true });
		if (done.kind !== "completed") throw new Error(done.reason);
		const read = await opened(w, keys, a.hash, done);
		expect(read.length).toBe(hpke.completionBuckets[1]);
		expect(read.payload.keys).toHaveLength(16);
	});

	it("shows a key with no label or time as `Passkey`, at 0, in the wire's form", async () => {
		const w = await world();
		const { a, keys, assertion, key } = await used(w);
		const done = await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true });
		if (done.kind !== "completed") throw new Error(done.reason);
		expect((await opened(w, keys, a.hash, done)).payload.keys).toEqual([
			{ credential_id: key.id, label: "Passkey", created_at: 0 },
		]);
	});

	it("answers the kept one alone where not asked to make one, writing nothing", async () => {
		const w = await world();
		const { a, assertion } = await used(w);
		const before = JSON.stringify(w.statements.value(a.hash));
		expect(await w.approvals.completePasskeyManage({ hash: a.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		expect(JSON.stringify(w.statements.value(a.hash))).toBe(before);
	});

	it("keeps none whose expiry passed while its list was read", async () => {
		const w = await world();
		const { a, assertion } = await used(w);
		w.advance(5 * 60_000 - 1);
		w.statements.beforeChange(a.hash, async () => w.advance(2));
		expect(
			await w.approvals.completePasskeyManage({ hash: a.hash, assertion, make: true }),
		).toEqual({ kind: "refused", reason: "expired" });
		expect(w.statements.value(a.hash)).toMatchObject({ state: "used" });
	});

	it("names no continuation but the one its record took and holds unanswered", async () => {
		const w = await world();
		const { a } = await used(w);
		const ask = (seq: number, bodyHash: string) =>
			w.approvals.completePasskeyManage({
				hash: a.hash,
				continued: { stage: "rename", seq, bodyHash },
			});
		// None taken yet.
		expect(await ask(1, sha256("b"))).toEqual({ kind: "refused", reason: "continued" });
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), seq: 2, body: sha256("b") } as never,
		}));
		// Taken, but held by no step: none.
		expect(await ask(2, sha256("b"))).toEqual({ kind: "refused", reason: "continued" });
		const holding = (until: number) =>
			w.statements.store.change(a.hash, (r) => ({
				value: { ...(r as object), claimed: { by: "t", until } } as never,
			}));
		// A hold lapsed: none either.
		await holding(Date.UTC(2020, 0, 1));
		expect(await ask(2, sha256("b"))).toEqual({ kind: "refused", reason: "continued" });
		await holding(Number.MAX_SAFE_INTEGER);
		expect(await ask(1, sha256("b"))).toEqual({ kind: "refused", reason: "continued" });
		expect(await ask(2, sha256("other"))).toEqual({ kind: "refused", reason: "continued" });
		expect(await ask(2, sha256("b"))).toMatchObject({ kind: "completed" });
		// Answered already: superseded.
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), result: "kept" } as never,
		}));
		expect(await ask(2, sha256("b"))).toEqual({ kind: "refused", reason: "continued" });
	});
});
