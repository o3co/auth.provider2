import type { Client } from "@mod/clients";
import { redirects } from "@mod/redirect-uris";
import { itemsFromJar } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { codeNeedsOver } from "../../code-needs/code-needs.ts";
import { itemMaxBytes, itemsRefusal, type RequestParts, requestsOver } from "../request.ts";

// A login's request checked after its JAR is verified, as the start and a push both ask it.

const issuer = "https://issuer.example";
const clientOf = (grants = ["authorization_code"]): Client => ({
	id: "c1",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>(s: { name: string }) =>
		(s.name === redirects.name
			? { "redirect-uris": ["https://rp.example/cb"] }
			: { grants, scopes: ["openid", "read"], audiences: ["https://api"] }) as T,
});
const client = clientOf();
const claims = (more: Record<string, unknown> = {}) =>
	Object.fromEntries(
		Object.entries({
			iss: "c1",
			aud: issuer,
			jti: "j1",
			nbf: 1,
			exp: 2,
			client_id: "c1",
			redirect_uri: "https://rp.example/cb",
			response_type: "code",
			response_mode: "form_post",
			state: "st",
			nonce: "n",
			scope: "read",
			code_challenge: "c".repeat(43),
			code_challenge_method: "S256",
			dpop_jkt: "jkt",
			...more,
		}).filter(([, v]) => v !== undefined),
	);
const verified = (c: Record<string, unknown>) =>
	({ kind: "verified", claims: c, jti: "j1", exp: 2 }) as const;
const checker = (over: Partial<RequestParts> & { idTokens?: boolean } = {}) =>
	requestsOver({
		claims: over.claims ?? { refusal: () => undefined },
		needs:
			over.needs ??
			codeNeedsOver({
				idTokens: over.idTokens ?? true,
				issuer,
				targets: undefined,
				bindings: {
					requestedOf: (param) =>
						param("dpop_jkt") === "jkt"
							? {
									kind: "requested",
									binding: { member: "jkt", confirmation: "jkt", tokenType: "DPoP" },
								}
							: { kind: "malformed", parameter: "dpop_jkt" },
				},
			}),
	});
const check = (c: Record<string, unknown>, at = client, parts = checker(), requestUri?: string) =>
	parts.check(at, verified(c), "jar-bytes", requestUri);
const refusal = (c: Record<string, unknown>, at?: Client, parts?: ReturnType<typeof checker>) => {
	const answer = check(c, at, parts);
	return "refused" in answer ? answer.refused : "items";
};

describe("a login's request checked", () => {
	it("answers T's items, naming the request_uri the start gives and none a push gives", () => {
		expect(check(claims())).toMatchObject({ items: { state: "st", scope: "read" } });
		const pushed = check(claims(), client, checker(), "urn:ietf:params:oauth:request_uri:x");
		expect(pushed).toMatchObject({ items: { request_uri: "urn:ietf:params:oauth:request_uri:x" } });
		expect("request_uri" in ((check(claims()) as { items: object }).items ?? {})).toBe(false);
	});

	it("reads the wire's spellings by one rule: a parameter's fault invalid_request, the request object's invalid_request_object", () => {
		// The spellings sdk-core-wire gives, pinned here, so a change of its text fails this test.
		const spelled = (c: Record<string, unknown>) => {
			const made = itemsFromJar(c, "h");
			return "error" in made ? made.error : "items";
		};
		expect(spelled(claims({ code_challenge: undefined }))).toBe("missing_item:code_challenge");
		expect(spelled(claims({ code_challenge_method: "plain" }))).toBe("item:code_challenge_method");
		expect(spelled(claims({ other: 1 }))).toBe("unknown_item:other");
		expect(spelled(claims({ claims: { id_token: { email: { essential: null } } } }))).toBe(
			"item:claims",
		);
		for (const [c, error] of [
			[claims({ code_challenge: undefined }), "invalid_request"],
			[claims({ code_challenge_method: undefined }), "invalid_request"],
			[claims({ code_challenge_method: "plain" }), "invalid_request"],
			[claims({ code_challenge_method: "S512" }), "invalid_request"],
			[claims({ state: undefined }), "invalid_request"],
			[claims({ nonce: undefined }), "invalid_request"],
			[claims({ response_mode: "query" }), "invalid_request"],
			[claims({ response_type: "token" }), "invalid_request"],
			[claims({ dpop_jkt: undefined }), "invalid_request"],
			[claims({ other: 1 }), "invalid_request_object"],
			[claims({ request_uri: "urn:x" }), "invalid_request_object"],
			[claims({ claims: { id_token: { email: { essential: null } } } }), "invalid_request_object"],
		] as const)
			expect(refusal(c), JSON.stringify(c)).toMatchObject({ error });
		expect(itemsRefusal("missing_item:state")).toEqual({
			error: "invalid_request",
			description: "missing_item:state",
		});
		// A spelling the rule does not know, or one naming nothing, is the request object's own.
		expect(itemsRefusal("some_other:state").error).toBe("invalid_request_object");
		expect(itemsRefusal("item:").error).toBe("invalid_request_object");
		expect(itemsRefusal("odd").error).toBe("invalid_request_object");
	});

	it("takes a state and a nonce of at most 512 bytes each, counted in UTF-8, the suite's 384-character nonce among them", () => {
		expect(itemMaxBytes).toBe(512);
		expect(check(claims({ state: "s".repeat(512), nonce: "n".repeat(384) }))).toHaveProperty(
			"items",
		);
		expect(check(claims({ nonce: "n".repeat(512) }))).toHaveProperty("items");
		expect(refusal(claims({ state: "s".repeat(513) }))).toEqual({
			error: "invalid_request",
			description: "state is longer than 512 bytes",
		});
		// The suite's 1000-character state: refused, which it marks a warning.
		expect(refusal(claims({ state: "s".repeat(1000) }))).toMatchObject({
			error: "invalid_request",
		});
		expect(refusal(claims({ nonce: "n".repeat(513) }))).toEqual({
			error: "invalid_request",
			description: "nonce is longer than 512 bytes",
		});
		// 171 three-byte characters are 513 bytes: counted as UTF-8, not as characters.
		expect(refusal(claims({ state: "あ".repeat(171) }))).toMatchObject({
			error: "invalid_request",
		});
		expect(check(claims({ state: "あ".repeat(170) }))).toHaveProperty("items");
		// A missing one is its own refusal first, and an over-long one comes before the needs.
		expect(refusal(claims({ state: undefined, nonce: "n".repeat(513) }))).toMatchObject({
			description: "missing_item:state",
		});
		expect(refusal(claims({ state: "s".repeat(513) }), clientOf([]))).toMatchObject({
			error: "invalid_request",
		});
	});

	it("answers prompt=none login_required, takes the words every tap meets, and refuses others", () => {
		expect(refusal(claims({ prompt: "none" }))).toEqual({
			error: "login_required",
			description: "every login asks the person's passkey",
		});
		expect(check(claims({ prompt: "login consent" }))).toHaveProperty("items");
		expect(refusal(claims({ prompt: "create" }))).toMatchObject({ error: "invalid_request" });
	});

	it("answers each need unmet by its code: the grant, the challenge, the scope, the binding", () => {
		expect(refusal(claims(), clientOf([]))).toMatchObject({ error: "unauthorized_client" });
		expect(refusal(claims({ code_challenge: "short" }))).toMatchObject({
			error: "invalid_request",
		});
		expect(refusal(claims({ scope: "write" }))).toMatchObject({ error: "invalid_scope" });
		expect(refusal(claims({ dpop_jkt: "bad" }))).toEqual({
			error: "invalid_request",
			description: "dpop_jkt is out of its form",
		});
		expect(refusal(claims({ resource: "https://api" }))).toMatchObject({ error: "invalid_target" });
		expect(refusal(claims({ scope: "openid read" }), client, checker({ idTokens: false }))).toEqual(
			{
				error: "invalid_scope",
				description: "no ID token is issued",
			},
		);
		const reader = checker({ claims: { refusal: (c) => (c === undefined ? undefined : "no") } });
		expect(refusal(claims({ claims: { id_token: {} } }), client, reader)).toEqual({
			error: "invalid_request_object",
			description: "no",
		});
	});

	it("answers the first fault in its order: the redirect URI, prompt, the items, OpenID, claims, then the needs", () => {
		const elsewhere = { redirect_uri: "https://evil.example/cb" };
		expect(refusal(claims({ ...elsewhere, prompt: "none" }))).toMatchObject({
			error: "invalid_request",
			description: "the redirect URI is not one the client registered",
		});
		expect(refusal(claims({ redirect_uri: undefined }))).toMatchObject({
			description: "the redirect URI is not one the client registered",
		});
		expect(refusal(claims({ prompt: "none", state: undefined }))).toMatchObject({
			error: "login_required",
		});
		expect(refusal(claims({ other: 1, scope: "write" }))).toMatchObject({
			error: "invalid_request_object",
		});
		const reader = checker({
			idTokens: false,
			claims: { refusal: () => "no" },
		});
		expect(refusal(claims({ scope: "openid read", claims: {} }), client, reader)).toMatchObject({
			description: "no ID token is issued",
		});
		expect(
			refusal(
				claims({ claims: {}, scope: "write" }),
				client,
				checker({ claims: { refusal: () => "no" } }),
			),
		).toMatchObject({
			error: "invalid_request_object",
		});
		expect(
			refusal(claims({ code_challenge: "short", scope: "write" }), clientOf([])),
		).toMatchObject({
			error: "unauthorized_client",
		});
	});
});
