import type { AccessGrant } from "@mod/tokens";
import { expect, it } from "vitest";
import { bundleOf, issuanceFor } from "../src/route/issuance.ts";

it("throws a session issuance's failure on, even where revoking the token fails too", async () => {
	const failing = (why: string) => async () => Promise.reject(new Error(why));
	const issued = { kind: "issued", access: { id: "a", expiresAt: 1, token: "t" } };
	const issuing = { issue: async () => issued, revokeReferenced: failing("revoking") };
	const { issue } = issuanceFor(issuing as never, "urn:test", undefined, [
		{ issued: failing("recording") },
	]);
	const access = { subject: "s", subjectKind: "user" as const, issuedTo: "c" };
	await expect(
		issue({ access: { ...access, audience: [], scope: [] } }, { session: "sid" }),
	).rejects.toThrow("recording");
});

it("notes the subject it hands tokens, reading the grant once", async () => {
	const signed: string[] = [];
	const issuing = {
		issue: async ({ request: { grant } }: { request: { grant: { subject: string } } }) => {
			signed.push(grant.subject);
			return { kind: "issued", access: { id: "a", expiresAt: 1, token: "t" } };
		},
	};
	const bundle = bundleOf();
	const { issue } = issuanceFor(issuing as never, "urn:test", undefined, [], bundle);
	let reads = 0;
	const grant = Object.defineProperty(
		{ subjectKind: "user", issuedTo: "c", audience: [], scope: [] },
		"subject",
		{
			enumerable: true,
			get: () => (++reads === 1 ? "bob" : "alice"),
		},
	) as unknown as AccessGrant;
	await issue({ access: grant });
	expect(reads).toBe(1);
	expect(signed).toEqual(["bob"]);
	expect([...bundle.subjects.values()]).toEqual([{ subject: "bob", subjectKind: "user" }]);
});

it("hands a bundle's root, its rooting and its parts on, and answers each part's token", async () => {
	const asked: unknown[] = [];
	const issuing = {
		issue: async (ask: unknown) => {
			asked.push(ask);
			return { kind: "issued", access: { id: "a", expiresAt: 1, token: "t" }, parts: ["id"] };
		},
	};
	const { issue } = issuanceFor(issuing as never, "urn:test", undefined);
	const part = {
		frame: "idToken" as const,
		prepare: async () => ({ prepared: 1, digest: "d" }),
		sign: async () => "id",
	};
	const access = {
		subject: "s",
		subjectKind: "user" as const,
		issuedTo: "c",
		audience: [],
		scope: [],
	};
	const answer = await issue({ access, root: "r", via: { via: "code" }, parts: [part] });
	expect(answer).toMatchObject({ kind: "issued", parts: ["id"] });
	expect(asked[0]).toMatchObject({ root: "r", via: { via: "code" }, parts: [part] });
	await issuanceFor(issuing as never, "urn:test", undefined).issue({ access });
	expect(Object.keys(asked[1] as object).sort()).toEqual(["limits", "request"]);
});
