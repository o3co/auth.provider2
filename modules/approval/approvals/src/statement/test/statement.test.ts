import { defineModule } from "@mod/kernel";
import { challengeInput, itemsFromJar, payloads, typs } from "@mod/sdk-core-wire";
import { tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	creationItems,
	issued,
	items,
	payloadOf,
	possessionItems,
	refusal,
} from "../../../test/fixtures/statements.ts";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import { type IssueAsk, statementItems } from "../../contract.ts";

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

	it("signs T whose JAR asks a claim by null, as itemsFromJar writes it ({}), and refuses a null before it is signed", async () => {
		const w = await world();
		const { jar_hash: _hash, ...jar } = items;
		const made = itemsFromJar({ ...jar, claims: { id_token: { email: null } } }, "jh");
		if (!("items" in made)) throw new Error(made.error);
		const t = await issued(w, { items: made.items } as Partial<IssueAsk>);
		expect(await w.keys.verify("core", t.statement, typs.statement)).toMatchObject({
			kind: "valid",
		});
		expect(payloadOf(t.statement).approval.claims).toEqual({ id_token: { email: {} } });
		const held = { ...made.items, claims: { id_token: { email: null } } };
		expect(await w.approvals.issue({ ...(await askOf()), items: held } as IssueAsk)).toMatchObject({
			kind: "refused",
			reason: "items",
		});
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
