import { continuations } from "@mod/continuation-wire";
import { defineModule } from "@mod/kernel";
import { challengeInput, hpke, payloads, typs } from "@mod/sdk-core-wire";
import { type Stage, transparency, transparencyLog } from "@mod/transparency";
import { tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { approvalKind, deciding } from "../src/completion/completion.ts";
import { passkeyAddCompletionsOver } from "../src/completion/passkey-add.ts";
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

	it("refuses one longer than its asker carries, as long, before it is signed or kept; one of that very length it signs", async () => {
		const w = await world();
		const length = (await issued(w)).statement.length;
		const created: string[] = [];
		const create = w.statements.store.create;
		w.statements.store.create = async (...args) => {
			created.push(args[0]);
			return create(...args);
		};
		const { screen } = screenKeys();
		const ask = { purpose: "authorization", items, screen, by: "src" } as const;
		expect(await w.approvals.issue({ ...ask, fits: length - 1 })).toEqual({
			kind: "refused",
			reason: "long",
		});
		expect(created).toEqual([]);
		// Its length, known before signing, is the signed statement's own.
		const fits = await w.approvals.issue({ ...ask, fits: length });
		if (fits.kind !== "issued") throw new Error(fits.reason);
		expect(fits.statement).toHaveLength(length);
		expect(created).toEqual([fits.hash]);
	});

	it("knows the length before signing for items JSON escapes and UTF-8 widens, and signs nothing it refuses long", async () => {
		const w = await world();
		const signed: unknown[] = [];
		const sign = w.keys.sign.bind(w.keys);
		w.keys.sign = async (...args) => {
			signed.push(args[0]);
			return sign(...args);
		};
		const { screen } = screenKeys();
		const state = `"\\\u0001é😀${"x".repeat(100)}`;
		const ask = {
			purpose: "authorization",
			items: { ...items, state },
			screen,
			by: "src",
		} as const;
		const first = await w.approvals.issue(ask);
		if (first.kind !== "issued") throw new Error(first.reason);
		expect(signed).toHaveLength(1);
		const length = first.statement.length;
		const long = { kind: "refused", reason: "long" };
		expect(await w.approvals.issue({ ...ask, fits: length - 1 })).toEqual(long);
		expect(signed).toHaveLength(1);
		const fits = await w.approvals.issue({ ...ask, fits: length });
		if (fits.kind !== "issued") throw new Error(fits.reason);
		expect(fits.statement).toHaveLength(length);
	});

	it("counts no statement refused long, as none refused for its items", async () => {
		const w = await world({ approvals: { "issue-limit": 1 } });
		const long = await w.approvals.issue({ ...(await askOf()), fits: 1 });
		expect(long).toEqual({ kind: "refused", reason: "long" });
		await issued(w);
		expect(await w.approvals.issue(await askOf())).toEqual({ kind: "refused", reason: "limited" });
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
		// An E_sig of no thumbprint, a point off the curve, is a key no ID token could name.
		const off = { ...screen, eSig: { ...screen.eSig, y: screen.eSig.x } };
		expect(await all.approvals.issue({ ...ask, screen: off })).toEqual({
			kind: "refused",
			reason: "items",
		});
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

	it.each(["passkey-add", "passkey-manage"] as const)(
		"refuses boot for any item of a %s, which names none",
		async (purpose) => {
			const filling = defineModule({ name: "odd", replicaSafe: true, takes: [] }, (m) => [
				m.contribute(statementItems).by(() => ({ purpose, names: ["amount"], by: "odd" })),
			]);
			await expect(world({ items: filling })).rejects.toMatchObject(
				refusal(new RegExp(`fills ${purpose}/amount`)),
			);
		},
	);

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
				// The asserting key's registration's record, as passkeys answered it.
				registration: "r0",
				usedAt: 1_800_000_000_000,
				issuedAt: 1_800_000_000_000,
				// The thumbprint of the screen's E_sig the statement was issued with (RFC 7638).
				esig: sha256(tokens.ecThumbprintInput(payloadOf(t.statement).e_sig) ?? "-"),
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

	it("answers what a used authorization rests on: its statement, the assertion as received and its credential", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const t = await issued(w);
		expect(await w.approvals.rootOf(t.hash)).toBeUndefined();
		const assertion = w.assert(t.challenge);
		await w.approvals.use({ statement: t.statement, assertion });
		expect(await w.approvals.rootOf(t.hash)).toEqual({
			statement: t.statement,
			assertion,
			credential: key.id,
		});
		expect(await w.approvals.rootOf("no-such-hash")).toBeUndefined();
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

	it("issues a passkey-add with no member of items, and uses it by an assertion, never a verification", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const { screen } = screenKeys();
		const a = await w.approvals.issue({ purpose: "passkey-add", items: {}, screen, by: "src" });
		if (a.kind !== "issued") throw new Error(a.reason);
		const payload = payloadOf(a.statement);
		expect(payloads.passkeyAdd.safeParse(payload).success).toBe(true);
		expect(payload).not.toHaveProperty("passkey-add");
		expect(await w.approvals.use({ statement: a.statement, verification: "v1" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		const assertion = w.assert(a.challenge);
		expect(await w.approvals.use({ statement: a.statement, assertion })).toMatchObject({
			kind: "approved",
			approval: {
				hash: a.hash,
				purpose: "passkey-add",
				items: {},
				subject: "s1",
				credential: key.id,
				registration: "r0",
			},
		});
	});

	it("gives a used passkey-add as its key change takes it, while it lives; none for another", async () => {
		const w = await world();
		const key = await w.plant("s1");
		const keys = screenKeys();
		const a = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: keys.screen,
			by: "src",
		});
		if (a.kind !== "issued") throw new Error(a.reason);
		// Not used yet: none.
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
		const assertion = w.assert(a.challenge);
		await w.approvals.use({ statement: a.statement, assertion });
		expect(await w.approvals.passkeyAddOf(a.hash)).toEqual({
			statement: a.statement,
			assertion,
			subject: "s1",
			credential: key.id,
			registration: "r0",
			screen: keys.screen,
			// The use-once mark the rules' fold names: the statement's id.
			mark: `statement:${payloadOf(a.statement).sid}`,
		});
		// An authorization used alike is none of it.
		const t = await issued(w);
		await w.approvals.use({ statement: t.statement, assertion: w.assert(t.challenge) });
		expect(await w.approvals.passkeyAddOf(t.hash)).toBeUndefined();
		// Past its statement's expiry, its record still kept: none.
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
	});

	it("gives no passkey-add used before its record held the key's registration", async () => {
		const w = await world();
		await w.plant("s1");
		const { screen } = screenKeys();
		const a = await w.approvals.issue({ purpose: "passkey-add", items: {}, screen, by: "src" });
		if (a.kind !== "issued") throw new Error(a.reason);
		await w.approvals.use({ statement: a.statement, assertion: w.assert(a.challenge) });
		await w.statements.store.change(a.hash, (r) => {
			const { registration: _gone, ...rest } = r as unknown as Record<string, unknown>;
			return { value: rest as never };
		});
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
	});

	it("gives no passkey-add whose bytes this generation's ring does not verify", async () => {
		const w = await world();
		await w.plant("s1");
		const { screen } = screenKeys();
		const a = await w.approvals.issue({ purpose: "passkey-add", items: {}, screen, by: "src" });
		if (a.kind !== "issued") throw new Error(a.reason);
		await w.approvals.use({ statement: a.statement, assertion: w.assert(a.challenge) });
		const [head, body] = a.statement.split(".");
		const other = `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`;
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), jws: other } as never,
		}));
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
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

describe("a key change's completion", () => {
	const named = { op: "add", credential_id: "cred", key_jkt: possessionItems.key_jkt };

	/** A possession issued for a screen, used by its pending key's verification. */
	async function usedPossession(w: Awaited<ReturnType<typeof world>>) {
		const keys = screenKeys();
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (p.kind !== "issued") throw new Error(p.reason);
		await w.approvals.use({ statement: p.statement, verification: "v1" });
		return { keys, p };
	}

	it("signs the key its possession names, sealed to its screen under its purpose and the possession's hash", async () => {
		const w = await world();
		const { keys, p } = await usedPossession(w);
		const asked = { hash: p.hash, purpose: "first-key" as const, receipt: "a.b.c" };
		const done = await w.approvals.completeKeyChange(asked);
		if (done.kind !== "completed") throw new Error(done.reason);
		const aad = hpke.completionAad("first-key", p.hash);
		const jws = openSealed(keys.encKey, done, hpke.info.completion, aad);
		expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
		const payload = payloadOf(jws);
		expect(payloads.completions.keyChange.safeParse(payload).success).toBe(true);
		expect(payload).toMatchObject({ purpose: "first-key", change: named, receipt: "a.b.c" });
		expect(payload.exp).toBe(payloadOf(p.statement).exp);
		// Under another purpose's additional data, or the bare hash, it does not open.
		for (const other of [hpke.completionAad("passkey-add", p.hash), p.hash]) {
			expect(() => openSealed(keys.encKey, done, hpke.info.completion, other)).toThrow();
		}
	});

	it("signs the possession's key, whatever else the caller hands", async () => {
		const w = await world();
		const { keys, p } = await usedPossession(w);
		const other = { op: "add", credential_id: "other", key_jkt: possessionItems.key_jkt };
		const asked = { hash: p.hash, purpose: "first-key" as const, change: other, extra: 1 };
		const done = await w.approvals.completeKeyChange(asked);
		if (done.kind !== "completed") throw new Error(done.reason);
		const aad = hpke.completionAad("first-key", p.hash);
		const payload = payloadOf(openSealed(keys.encKey, done, hpke.info.completion, aad));
		expect(payload.change).toEqual(named);
		expect(payload).not.toHaveProperty("extra");
	});

	it("signs no completion of a form sdk-core-wire refuses", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		expect(
			await w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key", receipt: "x" }),
		).toEqual({ kind: "refused", reason: "form" });
	});

	it("keeps one purpose of two asked at once, and refuses the other", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		const answers = await Promise.all([
			w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key" }),
			w.approvals.completeKeyChange({ hash: p.hash, purpose: "passkey-add" }),
		]);
		expect(answers.map((a) => a.kind).sort()).toEqual(["completed", "refused"]);
		expect(answers.find((a) => a.kind === "refused")).toEqual({ kind: "refused", reason: "other" });
	});

	it("answers the one kept for the same purpose, as the log first gave it, and refuses another", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		const [one, two] = await Promise.all([
			w.approvals.completeKeyChange({
				hash: p.hash,
				purpose: "passkey-add",
				status: '{"payload":"s"}',
			}),
			w.approvals.completeKeyChange({
				hash: p.hash,
				purpose: "passkey-add",
				status: '{"payload":"t"}',
			}),
		]);
		expect(one.kind).toBe("completed");
		expect(two).toEqual(one);
		expect(await w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key" })).toEqual({
			kind: "refused",
			reason: "other",
		});
	});

	it("answers no statement but a used possession unexpired, nor through the authorization's own calls", async () => {
		const w = await world();
		const t = await issued(w);
		const ask = (hash: string) =>
			w.approvals.completeKeyChange({ hash, purpose: "first-key" as const });
		expect(await ask(t.hash)).toEqual({ kind: "refused", reason: "purpose" });
		expect(await ask("none")).toEqual({ kind: "refused", reason: "unknown" });
		const keys = screenKeys();
		const unused = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (unused.kind !== "issued") throw new Error(unused.reason);
		expect(await ask(unused.hash)).toEqual({ kind: "refused", reason: "unused" });
		const { p } = await usedPossession(w);
		const done = await ask(p.hash);
		expect(done.kind).toBe("completed");
		// A possession's completion is no authorization's: none is published nor given so.
		expect(await w.approvals.complete({ hash: p.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(await w.approvals.publish(p.hash)).toBe("unknown");
		expect(await w.approvals.completionOf(p.hash)).toBeUndefined();
		expect(await w.approvals.usedOf(p.hash)).toMatchObject({ completed: true });
		const late = await usedPossession(w);
		// Past its expiry, kept a minute more, a change placed late completed then; then gone.
		w.advance(5 * 60_000 + 1000);
		expect(await ask(late.p.hash)).toMatchObject({ kind: "completed" });
		const later = await usedPossession(w);
		w.advance(5 * 60_000 + 60_000);
		expect(await ask(later.p.hash)).toEqual({ kind: "refused", reason: "unknown" });
		w.advance(60_000);
		expect(await ask(late.p.hash)).toEqual({ kind: "refused", reason: "unknown" });
	});
});

describe("a passkey-add's completion", () => {
	/** A passkey-add used by an assertion, and a creation issued for it to the same screen. */
	async function approved(w: Awaited<ReturnType<typeof world>>) {
		await w.plant("s1");
		const keys = screenKeys();
		const a = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: keys.screen,
			by: "src",
		});
		if (a.kind !== "issued") throw new Error(a.reason);
		const assertion = w.assert(a.challenge);
		await w.approvals.use({ statement: a.statement, assertion });
		const { ct_hash: _none, ...rest } = creationItems;
		const creationFor = async (items: object, screen = keys.screen) => {
			const c = await w.approvals.issue({
				purpose: "creation",
				// A member given as undefined is none: a sign-up's names no account.
				items: JSON.parse(
					JSON.stringify({ ...rest, basis: "passkey-add", evidence: a.hash, ...items }),
				) as never,
				screen,
				by: "s1",
			});
			if (c.kind !== "issued") throw new Error(c.reason);
			return c.statement;
		};
		return { keys, a, assertion, creation: await creationFor({}), creationFor };
	}

	it("signs the creation made for it, sealed to its screen under its purpose and hash, and keeps it", async () => {
		const w = await world();
		const { keys, a, assertion, creation, creationFor } = await approved(w);
		const done = await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation });
		if (done.kind !== "completed") throw new Error(done.reason);
		const opened = openSealed(
			keys.encKey,
			done,
			hpke.info.completion,
			hpke.completionAad("passkey-add", a.hash),
		);
		// Padded to the smaller bucket: none of its excluded keys is longer than 128 bytes.
		expect(opened).toHaveLength(hpke.completionBuckets[0]);
		const jws = hpke.unpaddedCompletion(opened) as string;
		expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
		const payload = payloadOf(jws);
		expect(payloads.completions.passkeyAdd.safeParse(payload).success).toBe(true);
		expect(payload).toMatchObject({
			purpose: "passkey-add",
			t_hash: a.hash,
			assertion_hash: sha256(assertion),
			creation,
		});
		// The one kept is answered, asked with no creation or another, and past the statement's expiry.
		const other = await creationFor({});
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual(done);
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation: other }),
		).toEqual(done);
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual(done);
		// Past its expiry the passkey-add is given no more; its record reads as used, its completion kept.
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
		expect(await w.approvals.usedOf(a.hash)).toMatchObject({
			purpose: "passkey-add",
			completed: true,
		});
	});

	it("keeps nothing where signing or sealing fails, and completes it when asked again", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const over = (keys: typeof w.keys) =>
			passkeyAddCompletionsOver({
				keys,
				store: w.statements.store,
				issuer: "https://issuer.example",
				now: () => 1_800_000_000_000,
			});
		const withdrawn = over({ ...w.keys, sign: async () => ({ kind: "withdrawn" }) as never });
		expect(await withdrawn({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "withdrawn",
		});
		const unsealed = over({
			...w.keys,
			seal: async () => {
				throw new Error("sealing fell");
			},
		});
		await expect(unsealed({ hash: a.hash, assertion, creation })).rejects.toThrow("sealing fell");
		// Still used, none kept: asked with no creation it answers none, and with one it completes.
		expect(await w.approvals.usedOf(a.hash)).not.toHaveProperty("completed");
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation }),
		).toMatchObject({
			kind: "completed",
		});
	});

	it("answers the one kept only to the assertion that used it", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const done = await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation });
		expect(done.kind).toBe("completed");
		const another = w.assert(a.challenge);
		for (const ask of [{ assertion: another }, { assertion: another, creation }])
			expect(await w.approvals.completePasskeyAdd({ hash: a.hash, ...ask })).toEqual({
				kind: "refused",
				reason: "assertion",
			});
	});

	it("makes none for a passkey-add whose bytes this generation's ring does not verify", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const [head, body] = a.statement.split(".");
		const other = `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`;
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), jws: other } as never,
		}));
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
	});

	it("is no authorization: completed or rooted as one, it answers none", async () => {
		const w = await world();
		const { a } = await approved(w);
		expect(await w.approvals.complete({ hash: a.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(await w.approvals.rootOf(a.hash)).toBeUndefined();
	});

	it("keeps one of two creations asked at once, and answers it to both", async () => {
		const w = await world();
		const { a, assertion, creation, creationFor } = await approved(w);
		const other = await creationFor({});
		const [one, two] = await Promise.all([
			w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation }),
			w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation: other }),
		]);
		expect(one.kind).toBe("completed");
		expect(two).toEqual(one);
	});

	it("signs no creation but one issued here for it, to its screen, and answers none kept yet", async () => {
		const w = await world();
		const { a, assertion, creationFor } = await approved(w);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		const refuses = async (creation: string) =>
			expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
				kind: "refused",
				reason: "creation",
			});
		// For another statement's evidence, another basis, or another screen's keys; or bytes not issued here.
		await refuses(await creationFor({ evidence: sha256("other") }));
		// A sign-up's creation names no account, its name in `user_name` alone.
		await refuses(
			await creationFor({
				basis: "sign-up",
				account: undefined,
				options: { ...creationItems.options, user_name: "Example 3fa9c1" },
			}),
		);
		await refuses(await creationFor({ subject: "s2" }));
		await refuses(await creationFor({}, screenKeys().screen));
		const [head, body] = (await creationFor({})).split(".");
		await refuses(`${head}.${body}.${Buffer.alloc(64).toString("base64url")}`);
	});

	it("answers no statement but a passkey-add used by that assertion, unexpired", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const another = w.assert(a.challenge);
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion: another, creation }),
		).toEqual({
			kind: "refused",
			reason: "assertion",
		});
		const t = await issued(w);
		const tAssertion = w.assert(t.challenge);
		await w.approvals.use({ statement: t.statement, assertion: tAssertion });
		expect(
			await w.approvals.completePasskeyAdd({ hash: t.hash, assertion: tAssertion, creation }),
		).toEqual({ kind: "refused", reason: "purpose" });
		const unused = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: screenKeys().screen,
			by: "src",
		});
		if (unused.kind !== "issued") throw new Error(unused.reason);
		expect(
			await w.approvals.completePasskeyAdd({ hash: unused.hash, assertion, creation }),
		).toEqual({ kind: "refused", reason: "unused" });
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});
});

describe("a continuation", () => {
	it("hands its step the creation as its record keeps it: the items signed and the screen's keys", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const handed: unknown[] = [];
		await w.approvals.continue({
			hash: c.hash,
			seq: 1,
			body: "b",
			signature: keys.signs(continuations.of("register", c.hash, 1, sha256("b"))),
			step: async (kept) => {
				handed.push(kept);
				return null;
			},
		});
		expect(handed).toEqual([{ items: creationItems, screen: keys.screen }]);
	});

	it("gives a creation's record, apart from a continuation, until it expires; no other purpose's", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued" || p.kind !== "issued") throw new Error("not issued");
		expect(await w.approvals.creationOf(c.hash)).toEqual({
			statement: c.statement,
			items: creationItems,
			screen: keys.screen,
		});
		expect(await w.approvals.creationOf(p.hash)).toBeUndefined();
		expect(await w.approvals.creationOf("unknown")).toBeUndefined();
		// A record whose bytes this generation's ring does not verify gives none.
		const [head, body] = c.statement.split(".");
		const other = `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`;
		await w.statements.store.change(c.hash, (r) => ({
			value: { ...(r as object), jws: other } as never,
		}));
		expect(await w.approvals.creationOf(c.hash)).toBeUndefined();
		const d = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (d.kind !== "issued") throw new Error(d.reason);
		expect(await w.approvals.creationOf(d.hash)).toBeDefined();
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.creationOf(d.hash)).toBeUndefined();
	});

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
				signature: signature ?? keys.signs(continuations.of("register", c.hash, seq, sha256(body))),
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
		const other = screenKeys().signs(continuations.of("register", c.hash, 2, sha256("b2")));
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

	it("refuses a body past 8192 bytes, and a signature in another spelling, taking nothing", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const ask = (body: string, signature: string) =>
			w.approvals.continue({ hash: c.hash, seq: 1, body, signature, step: async () => null });
		const big = "x".repeat(8193);
		expect(
			await ask(big, keys.signs(continuations.of("register", c.hash, 1, sha256(big)))),
		).toEqual({
			kind: "refused",
			reason: "body",
		});
		// The same 64 bytes, its last character's unused bits set: it verifies, and is refused.
		const sig = keys.signs(continuations.of("register", c.hash, 1, sha256("b1")));
		const last = sig.at(-1) as string;
		const spelt = `${sig.slice(0, -1)}${String.fromCharCode(last.charCodeAt(0) + 1)}`;
		expect(Buffer.from(spelt, "base64url")).toEqual(Buffer.from(sig, "base64url"));
		expect(await ask("b1", spelt)).toEqual({ kind: "refused", reason: "signature" });
		// Padded, of another length, or in base64's other alphabet: refused alike.
		const std = Buffer.from(sig, "base64url").toString("base64");
		for (const odd of [`${sig}==`, sig.slice(0, -2), `${sig}AA`, std.replace(/=+$/, "")])
			if (odd !== sig) expect(await ask("b1", odd)).toMatchObject({ reason: "signature" });
		// The bound counts UTF-8 bytes, not characters: 4096 two-byte characters pass, one more does not.
		const wide = "é".repeat(4096);
		const signedWide = (body: string) =>
			keys.signs(continuations.of("register", c.hash, 1, sha256(body)));
		expect(await ask(`${wide}é`, signedWide(`${wide}é`))).toEqual({
			kind: "refused",
			reason: "body",
		});
		expect(await ask(wide, signedWide(wide))).toMatchObject({ kind: "continued", seq: 1 });
		expect(w.statements.value(c.hash)).toMatchObject({ seq: 1 });
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
