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
	parts.checked(at, verified(c), "jar-bytes", requestUri);
const refusal = async (
	c: Record<string, unknown>,
	at?: Client,
	parts?: ReturnType<typeof checker>,
) => {
	const answer = await check(c, at, parts);
	return "refused" in answer ? answer.refused : "items";
};

describe("a login's request checked", () => {
	it("answers T's items, naming the request_uri the start gives and none a push gives", async () => {
		expect(await check(claims())).toMatchObject({ items: { state: "st", scope: "read" } });
		const pushed = await check(claims(), client, checker(), "urn:ietf:params:oauth:request_uri:x");
		expect(pushed).toMatchObject({ items: { request_uri: "urn:ietf:params:oauth:request_uri:x" } });
		expect("request_uri" in (((await check(claims())) as { items: object }).items ?? {})).toBe(
			false,
		);
	});

	it("reads the wire's spellings by one rule: a parameter's fault invalid_request, the request object's invalid_request_object", async () => {
		// The spellings sdk-core-wire gives, pinned here, so a change of its text fails this test.
		const spelled = (c: Record<string, unknown>) => {
			const made = itemsFromJar(c, "h");
			return "error" in made ? made.error : "items";
		};
		expect(spelled(claims({ code_challenge: undefined }))).toBe("missing_item:code_challenge");
		expect(spelled(claims({ code_challenge_method: "plain" }))).toBe("item:code_challenge_method");
		expect(spelled(claims({ authorization_details: [] }))).toBe(
			"refused_item:authorization_details",
		);
		// A claim no rule names is taken: no spelling, T made.
		expect(spelled(claims({ other: 1 }))).toBe("items");
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
			[claims({ authorization_details: [] }), "invalid_request_object"],
			[claims({ request_uri: "urn:x" }), "invalid_request_object"],
			[claims({ claims: { id_token: { email: { essential: null } } } }), "invalid_request_object"],
		] as const)
			expect(await refusal(c), JSON.stringify(c)).toMatchObject({ error });
		expect(itemsRefusal("missing_item:state")).toEqual({
			error: "invalid_request",
			description: "missing_item:state",
		});
		// A spelling the rule does not know, or one naming nothing, is the request object's own.
		expect(itemsRefusal("some_other:state").error).toBe("invalid_request_object");
		expect(itemsRefusal("item:").error).toBe("invalid_request_object");
		expect(itemsRefusal("odd").error).toBe("invalid_request_object");
	});

	it("takes a state and a nonce of at most 512 bytes each, counted in UTF-8, the suite's 384-character nonce among them", async () => {
		expect(itemMaxBytes).toBe(512);
		expect(await check(claims({ state: "s".repeat(512), nonce: "n".repeat(384) }))).toHaveProperty(
			"items",
		);
		expect(await check(claims({ nonce: "n".repeat(512) }))).toHaveProperty("items");
		expect(await refusal(claims({ state: "s".repeat(513) }))).toEqual({
			error: "invalid_request",
			description: "state is longer than 512 bytes",
		});
		// The suite's 1000-character state: refused, which it marks a warning.
		expect(await refusal(claims({ state: "s".repeat(1000) }))).toMatchObject({
			error: "invalid_request",
		});
		expect(await refusal(claims({ nonce: "n".repeat(513) }))).toEqual({
			error: "invalid_request",
			description: "nonce is longer than 512 bytes",
		});
		// 171 three-byte characters are 513 bytes: counted as UTF-8, not as characters.
		expect(await refusal(claims({ state: "あ".repeat(171) }))).toMatchObject({
			error: "invalid_request",
		});
		expect(await check(claims({ state: "あ".repeat(170) }))).toHaveProperty("items");
		// A missing one is its own refusal first, and an over-long one comes before the needs.
		expect(await refusal(claims({ state: undefined, nonce: "n".repeat(513) }))).toMatchObject({
			description: "missing_item:state",
		});
		expect(await refusal(claims({ state: "s".repeat(513) }), clientOf([]))).toMatchObject({
			error: "invalid_request",
		});
	});

	it("answers prompt=none login_required, takes the words every tap meets, and refuses others", async () => {
		expect(await refusal(claims({ prompt: "none" }))).toEqual({
			error: "login_required",
			description: "every login asks the person's passkey",
		});
		expect(await check(claims({ prompt: "login consent" }))).toHaveProperty("items");
		expect(await refusal(claims({ prompt: "create" }))).toMatchObject({ error: "invalid_request" });
		// A prompt of null is not sent (RFC 6749 §3.1), as the item rule reads any top-level null; "" is a word.
		expect(await check(claims({ prompt: null }))).toEqual(await check(claims()));
		expect(await refusal(claims({ prompt: "" }))).toMatchObject({ error: "invalid_request" });
	});

	it("answers each need unmet by its code: the grant, the challenge, the scope, the binding", async () => {
		expect(await refusal(claims(), clientOf([]))).toMatchObject({ error: "unauthorized_client" });
		expect(await refusal(claims({ code_challenge: "short" }))).toMatchObject({
			error: "invalid_request",
		});
		expect(await refusal(claims({ scope: "write" }))).toMatchObject({ error: "invalid_scope" });
		expect(await refusal(claims({ dpop_jkt: "bad" }))).toEqual({
			error: "invalid_request",
			description: "dpop_jkt is out of its form",
		});
		expect(await refusal(claims({ resource: "https://api" }))).toMatchObject({
			error: "invalid_target",
		});
		expect(
			await refusal(claims({ scope: "openid read" }), client, checker({ idTokens: false })),
		).toEqual({
			error: "invalid_scope",
			description: "no ID token is issued",
		});
		const reader = checker({ claims: { refusal: (c) => (c === undefined ? undefined : "no") } });
		expect(await refusal(claims({ claims: { id_token: {} } }), client, reader)).toEqual({
			error: "invalid_request_object",
			description: "no",
		});
	});

	it("answers the first fault in its order: the redirect URI, prompt, the items, OpenID, claims, then the needs", async () => {
		const elsewhere = { redirect_uri: "https://evil.example/cb" };
		expect(await refusal(claims({ ...elsewhere, prompt: "none" }))).toMatchObject({
			error: "invalid_request",
			description: "the redirect URI is not one the client registered",
		});
		expect(await refusal(claims({ redirect_uri: undefined }))).toMatchObject({
			description: "the redirect URI is not one the client registered",
		});
		expect(await refusal(claims({ prompt: "none", state: undefined }))).toMatchObject({
			error: "login_required",
		});
		expect(await refusal(claims({ authorization_details: [], scope: "write" }))).toMatchObject({
			error: "invalid_request_object",
		});
		const reader = checker({
			idTokens: false,
			claims: { refusal: () => "no" },
		});
		expect(
			await refusal(claims({ scope: "openid read", claims: {} }), client, reader),
		).toMatchObject({
			description: "no ID token is issued",
		});
		expect(
			await refusal(
				claims({ claims: {}, scope: "write" }),
				client,
				checker({ claims: { refusal: () => "no" } }),
			),
		).toMatchObject({
			error: "invalid_request_object",
		});
		expect(
			await refusal(claims({ code_challenge: "short", scope: "write" }), clientOf([])),
		).toMatchObject({
			error: "unauthorized_client",
		});
	});
});

describe("a login's request checked with its id_token_hint", () => {
	const hintOf = (sub: string) =>
		[
			"eyJhbGciOiJFUzI1NiJ9",
			Buffer.from(JSON.stringify({ sub })).toString("base64url"),
			"c2ln",
		].join(".");
	const reading = (answer: { subject: string } | { refused: string }) => {
		const read: [string, string][] = [];
		const parts = checker({
			claims: {
				refusal: () => undefined,
				hint: async (hint, clientId) => {
					read.push([hint, clientId]);
					return answer;
				},
			},
		});
		return { read, parts };
	};

	it("holds in T the subject the hint is verified for, the hint verified by the reader for the client", async () => {
		const { read, parts } = reading({ subject: "alice" });
		expect(await check(claims({ id_token_hint: hintOf("alice") }), client, parts)).toMatchObject({
			items: { hint_sub: "alice" },
		});
		expect(read).toEqual([[hintOf("alice"), "c1"]]);
	});

	it("refuses one verified for another subject than its payload reads as: no forged sub reaches T", async () => {
		const { parts } = reading({ subject: "mallory" });
		expect(await refusal(claims({ id_token_hint: hintOf("alice") }), client, parts)).toEqual({
			error: "invalid_request",
			description: "the id_token_hint reads as another subject than it is verified for",
		});
	});

	it("refuses, in the reader's words, one the reader refuses, and any where no module reads hints: never dropped", async () => {
		const { parts } = reading({
			refused: "the id_token_hint is not an ID token of this issuer (signature)",
		});
		expect(await refusal(claims({ id_token_hint: hintOf("alice") }), client, parts)).toEqual({
			error: "invalid_request",
			description: "the id_token_hint is not an ID token of this issuer (signature)",
		});
		expect(await refusal(claims({ id_token_hint: hintOf("alice") }))).toEqual({
			error: "invalid_request",
			description: "an id_token_hint is not read here",
		});
	});

	it("reads an id_token_hint of null as not sent: no reader asked, with or without one composed", async () => {
		const { read, parts } = reading({ subject: "alice" });
		expect(await check(claims({ id_token_hint: null }), client, parts)).toEqual(
			await check(claims(), client, parts),
		);
		expect(await check(claims({ id_token_hint: null }))).toEqual(await check(claims()));
		expect(read).toEqual([]);
	});

	it("asks no reader where the JAR has no hint, nor where the check refused first", async () => {
		const { read, parts } = reading({ subject: "alice" });
		expect(await check(claims(), client, parts)).toHaveProperty("items");
		expect(
			await refusal(claims({ id_token_hint: hintOf("alice"), state: undefined }), client, parts),
		).toMatchObject({
			error: "invalid_request",
		});
		expect(read).toEqual([]);
	});
});
