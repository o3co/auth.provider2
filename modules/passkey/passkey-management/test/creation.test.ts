import { randomBytes } from "node:crypto";
import type { IssueAsk } from "@mod/approvals";
import { payloads } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { nameOf } from "../src/account.ts";
import { creationItems, creationOver } from "../src/creation/creation.ts";

const screen = { eEnc: "E", eSig: { kty: "EC", crv: "P-256", x: "x", y: "y" } } as const;
/** The approving key a passkey-add's creation names (V30): a P-256 key, in passkey-key-wire's form. */
const approverKey = { kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43) } as const;
const ask = {
	subject: "s-alice",
	account: "a***@example.com",
	basis: "first-key" as const,
	evidence: "ev",
	ctHash: "ct",
	screen,
	since: 1000,
};

function creation(
	revoked = false,
	odd = false,
	full = false,
	named: { readonly accountName?: string; readonly rpId?: string } = {},
) {
	const asked: IssueAsk[] = [];
	const checked: [string, number][] = [];
	const handles: string[] = [];
	const names: string[] = [];
	const create = creationOver({
		approvals: {
			issue: async (a) => {
				asked.push(a);
				return { kind: "issued", statement: "s", hash: "h", challenge: "c" };
			},
		},
		ceremonies: {
			creation: (_challenge, user, exclude) => {
				handles.push(user.handle);
				names.push(user.name);
				if (odd) return { rp: {} };
				return {
					rp: { id: named.rpId ?? "login.example" },
					user: { id: user.handle },
					pubKeyCredParams: [{ alg: -7 }, { alg: -8 }],
					excludeCredentials: exclude.map((id) => ({ id })),
				};
			},
		},
		held: {
			of: async () => ({
				credentials: ["c1"],
				marked: false,
				...(full ? { full: true as const } : {}),
			}),
		},
		generations: { generation: async () => 2 },
		revocation: {
			check: async (subject, since) => {
				checked.push([subject, since]);
				return revoked ? "revoked" : "valid";
			},
		},
		random: (n) => randomBytes(n),
		accountName: named.accountName,
	});
	return { create, asked, handles, names, checked };
}

it("signs a creation naming the subject's key generation, its keys excluded, and a fresh handle", async () => {
	const c = creation();
	expect(await c.create(ask)).toMatchObject({ kind: "issued" });
	expect(c.asked).toEqual([
		{
			purpose: "creation",
			items: {
				account: "a***@example.com",
				basis: "first-key",
				evidence: "ev",
				ct_hash: "ct",
				subject: "s-alice",
				kg: 2,
				options: {
					user_id: c.handles[0],
					rp_id: "login.example",
					exclude_credentials: ["c1"],
					algorithms: [-7, -8],
				},
			},
			screen,
			by: "s-alice",
		},
	]);
	await c.create(ask);
	expect(c.handles[0]).not.toBe(c.handles[1]);
	expect(c.handles[0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

it("signs none for a subject revoked since its evidence began, asked of the subject and that time", async () => {
	const c = creation(true);
	expect(await c.create(ask)).toEqual({ kind: "refused", reason: "revoked" });
	expect(c.asked).toEqual([]);
	expect(c.checked).toEqual([["s-alice", 1000]]);
});

it("signs none where webauthn's options come of another shape", async () => {
	await expect(creation(false, true).create(ask)).rejects.toThrow(TypeError);
});

it("fills every creation item sdk-core-wire's schema names", () => {
	const named = Object.keys(payloads.creation.shape.creation.shape);
	expect([...creationItems.names].sort()).toEqual(named.sort());
});

it("names the approving key on a passkey-add's creation alone (V30)", async () => {
	const c = creation();
	const { ctHash: _first, ...rest } = ask;
	await c.create({ ...rest, basis: "passkey-add", approverKey });
	await c.create(ask);
	await c.create({ ...rest, basis: "sign-up" });
	expect(c.asked).toHaveLength(3);
	const [added, first, signUp] = c.asked;
	expect(added?.items).toMatchObject({ basis: "passkey-add", approver_key: approverKey });
	expect([first?.items, signUp?.items]).not.toContainEqual(
		expect.objectContaining({ approver_key: expect.anything() }),
	);
	expect(payloads.creation.shape.creation.safeParse(added?.items).success).toBe(true);
});

it("signs a passkey-add's creation with no ciphertext's hash, its account masked, as sdk-core-wire takes it", async () => {
	const c = creation();
	const { ctHash: _first, ...rest } = ask;
	await c.create({ ...rest, basis: "passkey-add", approverKey });
	const [asked] = c.asked;
	expect(asked?.items).toMatchObject({ basis: "passkey-add", account: "a***@example.com" });
	expect(asked?.items).not.toHaveProperty("ct_hash");
	expect(asked?.items).not.toHaveProperty("options.user_name");
	expect(payloads.creation.shape.creation.safeParse(asked?.items).success).toBe(true);
});

it("names a passkey-add's account no address names in `user_name`, by the RP ID and a mark of its subject", async () => {
	const c = creation();
	const { ctHash: _first, account: _masked, ...rest } = ask;
	await c.create({ ...rest, basis: "passkey-add", approverKey });
	const [asked] = c.asked;
	expect(asked?.items).not.toHaveProperty("account");
	expect(asked?.items).toMatchObject({
		options: { user_name: nameOf("login.example", "s-alice") },
	});
	// webauthn's options hold a place for the name, never read: the statement's is the name.
	expect(c.names).toEqual(["account"]);
	// sdk-core-wire takes one of the two, an account or a name, for any basis but the first key's.
	expect(payloads.creation.shape.creation.safeParse(asked?.items).success).toBe(true);
});

it("signs a sign-up's creation for its T, its account named in `user_name` alone", async () => {
	const c = creation();
	const { ctHash: _first, account: _masked, ...rest } = ask;
	await c.create({ ...rest, basis: "sign-up", evidence: "t-hash" });
	const [asked] = c.asked;
	expect(asked?.items).toMatchObject({
		basis: "sign-up",
		evidence: "t-hash",
		options: { user_name: nameOf("login.example", "s-alice") },
	});
	expect(asked?.items).not.toHaveProperty("account");
	expect(payloads.creation.shape.creation.safeParse(asked?.items).success).toBe(true);
});

it("refuses a creation of any basis for a subject full, asking nothing", async () => {
	const c = creation(false, false, true);
	expect(await c.create({ ...ask, basis: "passkey-add", approverKey })).toEqual({
		kind: "refused",
		reason: "full",
	});
	expect(await c.create(ask)).toEqual({ kind: "refused", reason: "full" });
	const { account: _, ctHash: __, ...rest } = ask;
	const signUp = { ...rest, basis: "sign-up" as const };
	expect(await c.create(signUp)).toEqual({ kind: "refused", reason: "full" });
	expect(c.asked).toEqual([]);
});

it("names an unnamed account by `account-name` where set, and by at most 50 of a long RP ID, within `user_name`'s 64", async () => {
	const { ctHash: _first, account: _masked, ...rest } = ask;
	const set = creation(false, false, false, { accountName: "Example" });
	await set.create({ ...rest, basis: "sign-up" });
	expect(set.asked[0]?.items).toMatchObject({
		options: { user_name: nameOf("Example", "s-alice") },
	});
	const rpId = `${"a".repeat(61)}.${"b".repeat(61)}.${"c".repeat(61)}.${"d".repeat(61)}.example`;
	const long = creation(false, false, false, { rpId });
	await long.create({ ...rest, basis: "sign-up" });
	const items = long.asked[0]?.items as { options: { user_name: string } };
	expect(items.options.user_name).toBe(nameOf(rpId.slice(0, 50), "s-alice"));
	expect(items.options.user_name.length).toBeLessThanOrEqual(64);
	expect(payloads.creation.shape.creation.safeParse(items).success).toBe(true);
	// A first key's masked account is its own: no name made.
	const first = creation(false, false, false, { accountName: "Example" });
	await first.create(ask);
	expect(first.asked[0]?.items).toMatchObject({ account: "a***@example.com" });
	expect(first.asked[0]?.items).not.toHaveProperty("options.user_name");
});
