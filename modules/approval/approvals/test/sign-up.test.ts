import { continuations } from "@mod/continuation-wire";
import { continuation } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import type { KeptSignUp, SignUpResult } from "../src/contract.ts";
import { screenKeys, sha256, world } from "./fixtures/world.ts";

// F1 (sign-up, the credential first; f1-shape r3): a T its owner allowed to be continued by sign-up,
// the start marked in the write that takes it, the subject and the creation kept on the T, the key's
// credential kept on the T by its key change's completion, and the T used by that credential alone.

const items = {
	...{ client_id: "c1", redirect_uri: "https://rp.example/cb", response_type: "code" as const },
	...{ response_mode: "form_post" as const, state: "st", scope: "openid", nonce: "n" },
	...{
		code_challenge: "cc",
		code_challenge_method: "S256" as const,
		dpop_jkt: "jkt",
		jar_hash: "jh",
	},
};
const options = { user_id: "u", rp_id: "rp.example", exclude_credentials: [], algorithms: [-7] };
const used = { kind: "refused", reason: "used" } as const;
const never = async (): Promise<SignUpResult> => {
	throw new Error("ran");
};

type World = Awaited<ReturnType<typeof world>>;
type T = Awaited<ReturnType<typeof tOf>>;

/** A T, allowed sign-up unless `allow` is false, with the screen's keys that sign its continuations. */
async function tOf(w: World, allow = true) {
	const keys = screenKeys();
	const continues = allow ? { continues: ["sign-up"] as const } : {};
	const t = await w.approvals.issue({
		...{ purpose: "authorization", items, screen: keys.screen, by: "src" },
		...continues,
	});
	if (t.kind !== "issued") throw new Error(t.reason);
	return { ...t, keys };
}

/** A creation for T's screen: a sign-up's (basis sign-up, T's hash its evidence) unless `made` is given. */
async function creationFor(w: World, t: T, subject = "s1", made?: object) {
	const signUp = { basis: "sign-up", evidence: t.hash, subject, kg: 0 };
	const own = { ...signUp, options: { ...options, user_name: "Example user 1a2b" } };
	const c = await w.approvals.issue({
		...{ purpose: "creation", screen: t.keys.screen, by: "s" },
		items: (made ?? own) as never,
	});
	if (c.kind !== "issued") throw new Error(c.reason);
	return c;
}

/** T's sign-up asked, its step answering `answer`. */
const signUp = (
	w: World,
	t: T,
	answer: (kept: KeptSignUp) => Promise<SignUpResult>,
	over: { seq?: number; body?: string; signature?: string } = {},
) => {
	const [seq, body] = [over.seq ?? 1, over.body ?? "{}"];
	const signature =
		over.signature ?? t.keys.signs(continuations.of("sign-up", t.hash, seq, sha256(body)));
	return w.approvals.continueSignUp({ hash: t.hash, seq, body, signature, step: answer });
};

/** A possession of `creation`, naming `credential`, used by its pending key's verification. */
async function possessionUsed(w: World, t: T, creation: string, credential: string) {
	const p = await w.approvals.issue({
		...{ purpose: "possession", screen: t.keys.screen, by: "s" },
		items: {
			...{ creation_hash: sha256(creation), credential_id: credential, reservation_id: "res" },
			key_jkt: "kZ8n9mX3tQ2vB7cY4wR1sE6uA0pL5dH9jF2gK8hN3oM",
		},
	});
	if (p.kind !== "issued") throw new Error(p.reason);
	const verified = await w.approvals.use({ statement: p.statement, verification: "v1" });
	if (verified.kind !== "approved") throw new Error(verified.reason);
	return p;
}

/** A T whose sign-up began, the subject made for it kept, its step answering its creation. */
async function begun(w: World, subject = "s1") {
	const t = await tOf(w);
	const c = await creationFor(w, t);
	await signUp(w, t, async (kept) => {
		await w.approvals.signUpSubject(kept.hash, subject);
		return { creation: c.statement };
	});
	return { t, c };
}

const complete = (w: World, hash: string, purpose: "sign-up" | "first-key" = "sign-up") =>
	w.approvals.completeKeyChange({ hash, purpose });
const useT = (w: World, t: T, assertion = w.assert(t.challenge)) =>
	w.approvals.use({ statement: t.statement, assertion });

describe("a T's sign-up (F1)", () => {
	it("hands its step the T as kept, marks it begun in the write that takes it, and answers the kept result again", async () => {
		const w = await world();
		const t = await tOf(w);
		expect(w.statements.value(t.hash).continues).toEqual(["sign-up"]);
		const handed: KeptSignUp[] = [];
		const c = await creationFor(w, t);
		const first = await signUp(w, t, async (kept) => {
			handed.push(kept);
			expect(w.statements.value(t.hash).signUp).toEqual({});
			return { creation: c.statement };
		});
		expect(first).toEqual({
			kind: "continued",
			seq: 1,
			again: false,
			result: { creation: c.statement },
		});
		expect(handed).toEqual([
			// T's issue time, as its signed `iat` says (the world's clock at its issue).
			{
				hash: t.hash,
				statement: t.statement,
				issuedAt: 1_800_000_000_000,
				items,
				screen: t.keys.screen,
			},
		]);
		// The same continuation again answers what was kept, its step not run again, even past T's expiry.
		w.advance(5 * 60_000 + 1000);
		expect(await signUp(w, t, never)).toEqual({ ...first, again: true });
	});

	it("is refused where its owner did not allow it, for another purpose, and through `continue`", async () => {
		const w = await world();
		const plain = await tOf(w, false);
		expect(w.statements.value(plain.hash).continues).toBeUndefined();
		expect(await signUp(w, plain, never)).toEqual({ kind: "refused", reason: "purpose" });
		expect(w.statements.value(plain.hash).signUp).toBeUndefined();
		const t = await tOf(w);
		const c = await creationFor(w, t);
		expect(await signUp(w, { ...t, hash: c.hash }, never)).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		// A T is no creation: `continue` (register) does not take it.
		const signature = t.keys.signs(continuation.of("register", t.hash, 1, sha256("{}")));
		const step = async () => null;
		expect(
			await w.approvals.continue({ hash: t.hash, seq: 1, body: "{}", signature, step }),
		).toEqual({ kind: "refused", reason: "purpose" });
	});

	it("takes the body {} and number 1 alone, signed over the sign-up stage's input", async () => {
		const w = await world();
		const t = await tOf(w);
		const refused = (reason: string) => ({ kind: "refused", reason });
		expect(await signUp(w, t, never, { body: '{"a":1}' })).toEqual(refused("body"));
		expect(await signUp(w, t, never, { body: "{ }" })).toEqual(refused("body"));
		expect(await signUp(w, t, never, { seq: 2 })).toEqual(refused("seq"));
		// The register stage's input, the same hash, number and body: another stage's words.
		const register = t.keys.signs(continuation.of("register", t.hash, 1, sha256("{}")));
		expect(await signUp(w, t, never, { signature: register })).toEqual(refused("signature"));
		expect(w.statements.value(t.hash).signUp).toBeUndefined();
	});

	it("is refused for a T used or expired, checked in the write that would take it", async () => {
		const w = await world();
		await w.plant("s0");
		const t = await tOf(w);
		expect((await useT(w, t)).kind).toBe("approved");
		expect(await signUp(w, t, never)).toEqual(used);
		const late = await tOf(w);
		w.advance(5 * 60_000 + 1000);
		expect(await signUp(w, late, never)).toEqual({ kind: "refused", reason: "expired" });
		expect(w.statements.value(late.hash).signUp).toBeUndefined();
	});

	it("runs its step again only within T's life, where the call that held it let its hold lapse", async () => {
		const w = await world();
		const t = await tOf(w);
		const c = await creationFor(w, t);
		let release: () => void = () => undefined;
		const held = signUp(
			w,
			t,
			() => new Promise((r) => (release = () => r({ creation: c.statement }))),
		);
		await new Promise((r) => setTimeout(r, 0));
		const answer = async (): Promise<SignUpResult> => ({ creation: c.statement });
		expect(await signUp(w, t, answer)).toEqual({ kind: "refused", reason: "pending" });
		// Its hold lapsed past T's expiry: the step is not run again.
		w.advance(5 * 60_000 + 1000);
		expect(await signUp(w, t, answer)).toEqual({ kind: "refused", reason: "expired" });
		release();
		await held;
	});

	it("answers the creation kept by the call that took a lapsed hold, to both calls; the other's is no T's", async () => {
		const w = await world();
		const t = await tOf(w);
		const [slow, fast] = [await creationFor(w, t, "s1"), await creationFor(w, t, "s2")];
		let release: () => void = () => undefined;
		const first = signUp(
			w,
			t,
			() => new Promise((r) => (release = () => r({ creation: slow.statement }))),
		);
		await new Promise((r) => setTimeout(r, 0));
		// Its hold lapses within T's life: another call runs the step again and keeps its answer.
		w.advance(31_000);
		const kept = { kind: "continued", result: { creation: fast.statement } };
		expect(await signUp(w, t, async () => ({ creation: fast.statement }))).toMatchObject(kept);
		release();
		expect(await first).toMatchObject(kept);
		expect((await w.approvals.signUpOf(t.hash))?.creation).toBe(fast.statement);
		const loser = await possessionUsed(w, t, slow.statement, "cred-a");
		expect(await complete(w, loser.hash)).toEqual({ kind: "refused", reason: "creation" });
	});

	it("keeps the first subject made for it, and none where no sign-up began", async () => {
		const w = await world();
		const t = await tOf(w);
		expect(await w.approvals.signUpSubject(t.hash, "s1")).toBeUndefined();
		await signUp(w, t, async () => {
			expect(await w.approvals.signUpSubject(t.hash, "s1")).toBe("s1");
			expect(await w.approvals.signUpSubject(t.hash, "s2")).toBe("s1");
			return { refused: "ledger" };
		});
		expect(w.statements.value(t.hash).signUp).toEqual({ subject: "s1" });
		// A refusal kept is no creation.
		expect(await w.approvals.signUpOf(t.hash)).toEqual({ statement: t.statement, subject: "s1" });
		expect(await w.approvals.signUpOf(sha256("unknown"))).toBeUndefined();
	});
});

describe("a sign-up's key, kept on its T, and the T's use", () => {
	it("keeps the possession's credential on T at its completion, and then T is used by that key", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const { t, c } = await begun(w);
		// Before its key is kept, T is used by none.
		expect(await useT(w, t)).toEqual(used);
		const p = await possessionUsed(w, t, c.statement, key.id);
		const done = await complete(w, p.hash);
		expect(done.kind).toBe("completed");
		expect(await w.approvals.signUpOf(t.hash)).toEqual({
			...{ statement: t.statement, subject: "s1" },
			...{ creation: c.statement, credential: key.id },
		});
		// Asked again, the one kept, and T keeps the same credential.
		expect(await complete(w, p.hash)).toEqual(done);
		const approved = await useT(w, t);
		expect(approved.kind === "approved" && approved.approval.credential).toBe(key.id);
	});

	it("is used by no other credential than the kept one, before passkeys is asked, nor by another subject", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const { t, c } = await begun(w);
		await complete(w, (await possessionUsed(w, t, c.statement, key.id)).hash);
		// Another credential's id over garbage: refused as used, not by passkeys' verification.
		const other = JSON.stringify({ ...JSON.parse(w.assert(t.challenge)), id: "other-cred" });
		expect(await useT(w, t, other)).toEqual(used);
		// The kept credential, but the subject made for the sign-up is another.
		const elsewhere = await begun(w, "s9");
		await complete(w, (await possessionUsed(w, elsewhere.t, elsewhere.c.statement, key.id)).hash);
		expect(await useT(w, elsewhere.t)).toEqual(used);
		// The planted key, the subject's own, is not the one a sign-up registered.
		const third = await begun(w);
		await complete(w, (await possessionUsed(w, third.t, third.c.statement, "cred-x")).hash);
		expect(await useT(w, third.t)).toEqual(used);
		expect(w.statements.value(third.t.hash).state).toBe("issued");
	});

	it("refuses a use whose read saw no sign-up, where a sign-up began before its write (marked)", async () => {
		const w = await world();
		await w.plant("s0");
		const t = await tOf(w);
		const c = await creationFor(w, t);
		// The sign-up is taken between the use's read (and its assertion) and the use's write.
		w.statements.beforeChange(t.hash, async () => {
			await signUp(w, t, async () => ({ creation: c.statement }));
		});
		expect(await useT(w, t)).toEqual(used);
		expect(w.statements.value(t.hash).state).toBe("issued");
		expect(w.statements.value(t.hash).signUp).toEqual({});
	});

	it("refuses in its write a use whose subject is not the one kept for the sign-up just before it", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const t = await tOf(w);
		const c = await creationFor(w, t);
		await signUp(w, t, async () => ({ creation: c.statement }));
		await complete(w, (await possessionUsed(w, t, c.statement, key.id)).hash);
		// Its subject is kept between the use's checks and its write: another than the key's.
		w.statements.beforeChange(t.hash, async () => {
			await w.approvals.signUpSubject(t.hash, "s9");
		});
		expect(await useT(w, t)).toEqual(used);
		expect(w.statements.value(t.hash).state).toBe("issued");
	});

	it("refuses a possession of no sign-up's creation, of another creation for T, or for another purpose", async () => {
		const w = await world();
		const { t, c } = await begun(w);
		const creation = { kind: "refused", reason: "creation" };
		const plain = await creationFor(w, t, "s1", {
			...{ account: "a***@example", evidence: "ev", ct_hash: "ct", subject: "s1", kg: 0 },
			options,
		});
		const p1 = await possessionUsed(w, t, plain.statement, "cred-c");
		expect(await complete(w, p1.hash)).toEqual(creation);
		const stray = await creationFor(w, t, "s9");
		const p2 = await possessionUsed(w, t, stray.statement, "cred-d");
		expect(await complete(w, p2.hash)).toEqual(creation);
		const p3 = await possessionUsed(w, t, c.statement, "cred-a");
		expect(await complete(w, p3.hash, "first-key")).toEqual(creation);
		expect((await w.approvals.signUpOf(t.hash))?.credential).toBeUndefined();
	});

	it("keeps one credential of two possessions at once, refuses the other, and keeps it past a later fault", async () => {
		const w = await world();
		const { t, c } = await begun(w);
		const a = await possessionUsed(w, t, c.statement, "cred-a");
		const b = await possessionUsed(w, t, c.statement, "cred-b");
		const answers = await Promise.all([complete(w, a.hash), complete(w, b.hash)]);
		const kept = (await w.approvals.signUpOf(t.hash))?.credential;
		expect(answers.map((x) => x.kind).sort()).toEqual(["completed", "refused"]);
		expect(answers[kept === "cred-a" ? 1 : 0]).toEqual({ kind: "refused", reason: "other" });
		// The credential is kept before the completion: a fault between them leaves it, asked again completes.
		const next = await begun(w);
		const p = await possessionUsed(w, next.t, next.c.statement, "cred-e");
		w.statements.beforeChange(p.hash, async () => {
			throw new Error("the store fell");
		});
		await expect(complete(w, p.hash)).rejects.toThrow("the store fell");
		expect((await w.approvals.signUpOf(next.t.hash))?.credential).toBe("cred-e");
		expect((await complete(w, p.hash)).kind).toBe("completed");
	});
});
