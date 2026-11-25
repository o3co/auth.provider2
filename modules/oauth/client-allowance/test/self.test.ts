import type { Client } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { clientAllowance } from "../src/contract.ts";
import { type Allowances, allowances } from "../src/metadata.ts";

const issuer = "https://as";

/** A client whose `client-allowance` section holds these values, of a signed version unless said. */
const holding = (section: Partial<Allowances>, signed = true): Client => ({
	id: "svc",
	kind: "confidential",
	method: "private_key_jwt",
	registered: false,
	version: 2,
	...(signed ? { signed: true as const } : {}),
	section: <T>() => ({ grants: [], scopes: ["human"], audiences: [], self: [], ...section }) as T,
});

const read = (value: unknown) => {
	const checked = allowances.schema["~standard"].validate(value);
	if (checked instanceof Promise) throw new Error("not synchronous");
	return checked;
};

describe("the client's own ceiling", () => {
	const { allowedSelfIssuance, selfAudiences } = clientAllowance;
	const one = holding({ self: [{ audience: "https://api", scopes: ["read", "write"] }] });
	const two = holding({
		self: [
			{ audience: "https://api", scopes: ["read"] },
			{ audience: "https://reports", scopes: ["export"] },
		],
	});

	it("is empty by default, so a client is issued nothing for itself", () => {
		expect(read({}).issues).toBeUndefined();
		expect((read({}) as { value: Allowances }).value.self).toEqual([]);
		const none = holding({});
		expect(selfAudiences(none)).toEqual([]);
		expect(allowedSelfIssuance(none, "read", [], issuer)).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
	});

	it("issues the scopes named, all within the one entry, its audience when the request names none", () => {
		expect(allowedSelfIssuance(one, "read write read", [], issuer)).toEqual({
			kind: "allowed",
			scope: ["read", "write"],
			audience: ["https://api"],
		});
		expect(allowedSelfIssuance(one, "read", ["https://api"], issuer)).toMatchObject({
			kind: "allowed",
			audience: ["https://api"],
		});
	});

	it("never reads the person's delegation: its scopes and audiences give the client nothing for itself", () => {
		const delegated = holding({ scopes: ["read"], "default-scopes": ["read"], audiences: ["x"] });
		expect(allowedSelfIssuance(delegated, "read", ["x"], issuer).kind).toBe("error");
		expect(allowedSelfIssuance(one, "human", [], issuer)).toEqual({
			kind: "error",
			error: "invalid_scope",
		});
	});

	it("requires the scope named, with no default", () => {
		for (const requested of [undefined, ""]) {
			expect(allowedSelfIssuance(one, requested, [], issuer)).toEqual({
				kind: "error",
				error: "invalid_scope",
				description: "scope is required",
			});
		}
		expect(allowedSelfIssuance(one, "read  write", [], issuer)).toEqual({
			kind: "error",
			error: "invalid_scope",
		});
	});

	it("issues by pair: a scope of another entry's audience is outside", () => {
		expect(allowedSelfIssuance(two, "export", ["https://api"], issuer)).toEqual({
			kind: "error",
			error: "invalid_scope",
		});
		expect(allowedSelfIssuance(two, "export", ["https://reports"], issuer)).toMatchObject({
			kind: "allowed",
			scope: ["export"],
			audience: ["https://reports"],
		});
	});

	it("requires the audience named where it holds two entries or more, and one audience alone", () => {
		expect(allowedSelfIssuance(two, "read", [], issuer)).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
		expect(
			allowedSelfIssuance(two, "read", ["https://api", "https://reports"], issuer),
		).toMatchObject({ kind: "error", error: "invalid_target" });
		expect(allowedSelfIssuance(one, "read", ["https://elsewhere"], issuer)).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
		expect(selfAudiences(two)).toEqual(["https://api", "https://reports"]);
	});

	it("never names the issuer as the audience, and issues nothing to a client whose ceiling writes it", () => {
		const written = holding({
			self: [
				{ audience: issuer, scopes: ["read"] },
				{ audience: "https://api", scopes: ["read"] },
			],
		});
		const refused = {
			kind: "error",
			error: "unauthorized_client",
			description: "the client's own ceiling names the issuer",
		};
		for (const audience of [[], [issuer], ["https://api"]])
			expect(allowedSelfIssuance(written, "read", audience, issuer)).toEqual(refused);
		expect(allowedSelfIssuance(one, "read", [issuer], issuer)).toMatchObject({
			kind: "error",
			error: "invalid_target",
		});
	});

	it("is a signed version's alone: a client its source does not declare signed has none", () => {
		const unsigned = holding({ self: [{ audience: "https://api", scopes: ["read"] }] }, false);
		expect(selfAudiences(unsigned)).toEqual([]);
		expect(allowedSelfIssuance(unsigned, "read", [], issuer)).toMatchObject({
			kind: "error",
			error: "unauthorized_client",
		});
	});

	it("refuses a record naming an audience in two entries, or offline_access or openid among an entry's scopes", () => {
		const twice = read({
			self: [
				{ audience: "https://api", scopes: ["read"] },
				{ audience: "https://api", scopes: ["write"] },
			],
		});
		expect(twice.issues?.map((i) => i.path)).toEqual([["self", 1, "audience"]]);
		const offline = read({ self: [{ audience: "https://api", scopes: ["offline_access"] }] });
		expect(offline.issues?.map((i) => i.path)).toEqual([["self", 0, "scopes", 0]]);
		const openid = read({ self: [{ audience: "https://api", scopes: ["read", "openid"] }] });
		expect(openid.issues?.map((i) => [i.path, i.message])).toEqual([
			[
				["self", 0, "scopes", 1],
				"openid asks for a person's identity, which a client's own token never carries, so remove it",
			],
		]);
		// The person's delegation keeps openid: a client asks it for a person.
		expect(read({ scopes: ["openid"] }).issues).toBeUndefined();
	});
});
