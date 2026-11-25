import { randomBytes } from "node:crypto";
import type { IssueAsk } from "@mod/approvals";
import { payloads } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { creationItems, creationOver } from "../src/creation/creation.ts";

const screen = { eEnc: "E", eSig: { kty: "EC", crv: "P-256", x: "x", y: "y" } } as const;
const ask = {
	subject: "s-alice",
	account: "a***@example.com",
	basis: "first-key" as const,
	evidence: "ev",
	ctHash: "ct",
	screen,
	since: 1000,
};

function creation(revoked = false, odd = false) {
	const asked: IssueAsk[] = [];
	const checked: [string, number][] = [];
	const handles: string[] = [];
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
				if (odd) return { rp: {} };
				return {
					rp: { id: "login.example" },
					user: { id: user.handle },
					pubKeyCredParams: [{ alg: -7 }, { alg: -8 }],
					excludeCredentials: exclude.map((id) => ({ id })),
				};
			},
		},
		held: { of: async () => ({ credentials: ["c1"], marked: false }) },
		generations: { generation: async () => 2 },
		revocation: {
			check: async (subject, since) => {
				checked.push([subject, since]);
				return revoked ? "revoked" : "valid";
			},
		},
		random: (n) => randomBytes(n),
	});
	return { create, asked, handles, checked };
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
