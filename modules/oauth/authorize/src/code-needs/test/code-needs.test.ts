import type { Client } from "@mod/clients";
import { redirects } from "@mod/redirect-uris";
import type { AuthorizationItems } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { codeNeedsOver } from "../code-needs.ts";

// What a code needs, as the start checks it before T and the finish again before the session.

const issuer = "https://issuer.example";
const clientOf = (grants: string[], audiences: string[] = []): Client => ({
	id: "c1",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>(s: { name: string }) =>
		(s.name === redirects.name
			? { "redirect-uris": ["https://rp.example/cb"] }
			: { grants, scopes: ["openid", "read"], audiences }) as T,
});
const items = (over: Partial<AuthorizationItems> = {}) =>
	({
		client_id: "c1",
		scope: "read",
		code_challenge: "c".repeat(43),
		code_challenge_method: "S256",
		dpop_jkt: "jkt",
		...over,
	}) as AuthorizationItems;
const needs = (over: { idTokens?: boolean; rule?: boolean } = {}) =>
	codeNeedsOver({
		idTokens: over.idTokens ?? true,
		issuer,
		targets: over.rule
			? { target: (q) => ({ kind: "allowed", audience: [q.param("resource") ?? ""] }) as never }
			: undefined,
		bindings: {
			requestedOf: (param) => {
				const jkt = param("dpop_jkt");
				return jkt === "jkt"
					? {
							kind: "requested",
							binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" },
						}
					: { kind: "none" };
			},
		},
	});
const code = clientOf(["authorization_code"], ["https://api"]);

describe("what a code needs", () => {
	it("is met at the start and the finish alike for a code's client, an S256 challenge and a binding asked", () => {
		const n = needs();
		expect(n.atStart(code, items())).toBeUndefined();
		expect(n.atFinish(code, items())).toMatchObject({
			scope: ["read"],
			binding: { confirmation: "jkt" },
		});
	});

	it("tells the need unmet, by its word, in the order each side checks", () => {
		const n = needs();
		const noGrant = clientOf(["client_credentials"]);
		expect(n.atStart(noGrant, items({ code_challenge: "x" }))).toEqual({ need: "grant" });
		expect(n.atStart(code, items({ code_challenge: "x" }))).toEqual({ need: "challenge" });
		expect(n.atStart(code, items({ dpop_jkt: "other" }))).toEqual({ need: "binding" });
		expect(n.atFinish(noGrant, items())).toEqual({ need: "grant" });
		expect(n.atFinish(code, items({ code_challenge: "x" }))).toEqual({ need: "challenge" });
		expect(n.atFinish(code, items({ scope: "write" }))).toEqual({ need: "scope" });
		expect(n.atFinish(code, items({ dpop_jkt: "other" }))).toEqual({ need: "binding" });
	});

	it("reads a resource by the one rule at the start, none composed leaving it unmet; at the finish, within the client's audiences", () => {
		const asked = items({ resource: "https://api" });
		expect(needs().atStart(code, asked)).toEqual({
			need: "resource",
			description: "resource is read by no rule here",
		});
		expect(needs({ rule: true }).atStart(code, asked)).toBeUndefined();
		expect(needs().atFinish(code, asked)).toMatchObject({ audience: ["https://api"] });
		expect(needs().atFinish(code, items({ resource: "https://other" }))).toEqual({
			need: "resource",
		});
	});

	it("leaves an OpenID request unmet where no ID token is made", () => {
		const openid = items({ scope: "openid read" });
		expect(needs({ idTokens: false }).openidUnmet(openid)).toBe(true);
		expect(needs().openidUnmet(openid)).toBe(false);
		expect(needs().asksOpenid(["openid", "read"])).toBe(true);
		expect(needs().asksOpenid("read")).toBe(false);
	});
});
