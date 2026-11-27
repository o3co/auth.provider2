import type { AuthorizationRequests } from "@mod/authorize";
import { authorizationRequestsOf, authorizationRequestsStandIn } from "@mod/authorize/testing";
import type { Client } from "@mod/clients";
import { overHttp } from "@mod/front-core-wire";
import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { Unavailable } from "@mod/kernel";
import { redirects } from "@mod/redirect-uris";
import { typs } from "@mod/sdk-core-wire";
import type { BindingOutcome, SenderBindings } from "@mod/sender-binding";
import { describe, expect, it } from "vitest";
import type { PushedRequests, StoredPush } from "../src/contract.ts";
import { parPath, pushedSource, pushing, requestUriPrefix } from "../src/push/push.ts";

const now = 1_800_000_000_000;
const issuer = "https://issuer.example";
const client = {
	id: "c1",
	kind: "confidential",
	method: "private_key_jwt",
	registered: true,
} as Client;

const claims = (more: Record<string, unknown> = {}) => ({
	iss: "c1",
	client_id: "c1",
	aud: issuer,
	jti: "j1",
	nbf: now / 1000,
	exp: now / 1000 + 60,
	dpop_jkt: "jkt-1",
	...more,
});
const jar = (payload: Record<string, unknown>, by = "c1") =>
	`h.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${by}`;

function memoryPushed() {
	const kept = new Map<string, { value: StoredPush; until: number }>();
	const pushed: PushedRequests = {
		async create(key, record, lifetimeMs) {
			if (kept.has(key)) return "exists";
			kept.set(key, { value: record, until: now + lifetimeMs });
			return "created";
		},
		read: async (key) => kept.get(key)?.value,
	};
	return { pushed, kept };
}

function harness(
	p: {
		proved?: BindingOutcome;
		authenticated?: boolean;
		/** How long checking the proof takes, in ms; none unless told. */
		proofMs?: number;
		/** authorize's check of the request; its stand-in unless told. */
		requests?: (bindings: Pick<SenderBindings, "requestedOf">) => AuthorizationRequests;
		/** The client authenticated; one with no section unless told. */
		client?: Client;
	} = {},
) {
	const store = memoryPushed();
	let n = 0;
	let clock = now;
	let proofs = 0;
	const bindings: Pick<SenderBindings, "bindingOf" | "requestedOf"> = {
		bindingOf: async () => {
			proofs += 1;
			clock += p.proofMs ?? 0;
			return p.proved ?? { kind: "none" };
		},
		requestedOf: (param) => {
			const jkt = param("dpop_jkt");
			if (jkt === "bad") return { kind: "malformed", parameter: "dpop_jkt" };
			return jkt === undefined
				? { kind: "none" }
				: { kind: "requested", binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" } };
		},
	};
	const push = pushing({
		clients: {
			authenticate: async () =>
				p.authenticated === false
					? { kind: "refused", reason: "bad_credentials", challenges: [] }
					: { kind: "authenticated", client: p.client ?? client, challenges: [] },
		} as never,
		requests: p.requests?.(bindings) ?? authorizationRequestsStandIn(),
		assertion: {
			verifySignedBy: async (c, jwt, typ) => {
				const [, payload, by] = jwt.split(".");
				if (typ !== typs.jar || by !== c.id) return { kind: "refused", reason: "signature" };
				return {
					kind: "signed",
					claims: JSON.parse(Buffer.from(payload ?? "", "base64url").toString()),
				};
			},
		},
		bindings,
		pushed: store.pushed,
		issuer,
		maxLifetimeS: 90,
		skewS: 30,
		now: () => clock,
		token: () => {
			n += 1;
			return `t${n}`;
		},
	});
	const send = async (form: Record<string, string> | readonly (readonly [string, string])[]) => {
		const pairs = Array.isArray(form) ? form : Object.entries(form);
		const fields = new Map<string, string[]>();
		for (const [k, v] of pairs) fields.set(k, [...(fields.get(k) ?? []), v]);
		const request: HttpRequest = testRequest({ method: "POST", path: parPath, fields });
		const r = await push(request);
		return {
			status: r.status,
			json: (r.body as { json: Record<string, unknown> }).json,
			headers: r.headers ?? {},
		};
	};
	return { send, store, proofs: () => proofs };
}

describe("a pushed authorization request", () => {
	it("keeps the client's JAR under a fresh request_uri, for its JAR's life", async () => {
		const h = harness();
		const r = await h.send({ request: jar(claims()) });
		expect(r).toMatchObject({
			status: 201,
			json: { request_uri: `${requestUriPrefix}t1`, expires_in: 60 },
		});
		expect(h.store.kept.get(`${requestUriPrefix}t1`)?.until).toBe(now + 90_000);
	});

	it("refuses an unauthenticated client, another client's JAR, and a JAR not for this issuer", async () => {
		expect(await harness({ authenticated: false }).send({ request: jar(claims()) })).toMatchObject({
			status: 401,
			json: { error: "invalid_client" },
		});
		const h = harness();
		expect(await h.send({ request: jar(claims(), "c2") })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims({ iss: "c2" })) })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims({ aud: "https://other.example" })) })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims()), client_id: "c2" })).toMatchObject({
			json: { error: "invalid_request" },
		});
	});

	it("refuses a JAR expired, living too long, or naming no jti", async () => {
		const h = harness();
		for (const more of [{ exp: now / 1000 }, { exp: now / 1000 + 91 }, { jti: undefined }])
			expect(await h.send({ request: jar(claims(more)) })).toMatchObject({
				status: 400,
				json: { error: "invalid_request_object" },
			});
		expect(h.store.kept.size).toBe(0);
	});

	it("takes a DPoP proof of the key the JAR names, and refuses one of another (A44)", async () => {
		const proof = (confirmation: string): BindingOutcome => ({
			kind: "bound",
			binding: { member: "jkt", confirmation, tokenType: "DPoP" },
		});
		expect(
			await harness({ proved: proof("jkt-1") }).send({ request: jar(claims()) }),
		).toMatchObject({ status: 201 });
		expect(
			await harness({ proved: proof("jkt-2") }).send({ request: jar(claims()) }),
		).toMatchObject({
			status: 400,
			json: { error: "invalid_dpop_proof" },
		});
		const refusedProof: BindingOutcome = {
			kind: "refused",
			error: "invalid_dpop_proof",
			description: "bad",
		};
		expect(await harness({ proved: refusedProof }).send({ request: jar(claims()) })).toMatchObject({
			json: { error: "invalid_dpop_proof" },
		});
	});

	it("gives back the binding kind's headers with its refusal, so a client may take the nonce asked", async () => {
		const nonce: BindingOutcome = {
			kind: "refused",
			error: "use_dpop_nonce",
			description: "a nonce is asked",
			headers: { "dpop-nonce": "n1" },
		};
		const r = await harness({ proved: nonce }).send({ request: jar(claims()) });
		expect(r).toMatchObject({ status: 400, json: { error: "use_dpop_nonce" } });
		expect(r.headers).toMatchObject({ "dpop-nonce": "n1" });
	});

	it("answers the request's check's refusal in its own word, before any proof is read or anything kept", async () => {
		for (const refusal of [
			{ error: "invalid_request", description: "missing_item:code_challenge" },
			{ error: "login_required", description: "every login asks the person's passkey" },
		]) {
			const h = harness({
				requests: () => authorizationRequestsStandIn(() => ({ refused: refusal })),
			});
			expect(await h.send({ request: jar(claims()) })).toEqual({
				status: 400,
				json: { error: refusal.error, error_description: refusal.description },
				headers: expect.anything(),
			});
			expect(h.proofs()).toBe(0);
			expect(h.store.kept.size).toBe(0);
		}
	});

	it("is unavailable, reading no proof and keeping nothing, where the checked items name no binding the kind reads (A44 never skipped)", async () => {
		for (const dpop_jkt of [undefined, "bad"]) {
			const h = harness({
				requests: () =>
					authorizationRequestsStandIn((v) => ({ items: { ...v.claims, dpop_jkt } as never })),
			});
			await expect(h.send({ request: jar(claims()) })).rejects.toBeInstanceOf(Unavailable);
			expect(h.proofs()).toBe(0);
			expect(h.store.kept.size).toBe(0);
		}
	});

	it("refuses two bindings, is unavailable where the kind cannot tell, and takes another kind's binding", async () => {
		expect(
			await harness({ proved: { kind: "multiple_bindings" } }).send({ request: jar(claims()) }),
		).toMatchObject({
			json: { error: "invalid_request" },
		});
		const unknown: BindingOutcome = { kind: "refused", error: "x", unavailable: true };
		await expect(harness({ proved: unknown }).send({ request: jar(claims()) })).rejects.toThrow();
		const ambient: BindingOutcome = {
			kind: "bound",
			binding: { member: "x5t#S256", confirmation: "c", tokenType: "Bearer" },
		};
		expect(await harness({ proved: ambient }).send({ request: jar(claims()) })).toMatchObject({
			status: 201,
		});
	});

	it("refuses a request_uri and authorization_details sent with the push (RFC 9126 §2.1)", async () => {
		const h = harness();
		expect(await h.send({ request: jar(claims()), request_uri: "other" })).toMatchObject({
			json: { error: "invalid_request" },
		});
		expect(await h.send({ request: jar(claims()), authorization_details: "other" })).toMatchObject({
			json: { error: "invalid_request" },
		});
	});

	it("refuses any parameter sent twice before reading one (RFC 6749 §3.1): authorization_details twice among them", async () => {
		const h = harness();
		const twice = (name: string, value: string) =>
			h.send([
				["request", jar(claims())],
				[name, value],
				[name, value],
			]);
		for (const [name, value] of [
			["authorization_details", "[]"],
			["request_uri", "other"],
			["client_id", "c1"],
			["dpop_jkt", "jkt"],
		] as const)
			expect(await twice(name, value), name).toMatchObject({
				status: 400,
				json: { error: "invalid_request", error_description: "repeated parameter" },
			});
		expect(
			await h.send([
				["request", jar(claims())],
				["request", jar(claims())],
			]),
		).toMatchObject({
			status: 400,
			json: { error: "invalid_request", error_description: "repeated parameter" },
		});
		expect(h.store.kept.size).toBe(0);
		// Before the client is authenticated: an unauthenticated push sent so is this refusal, not a 401.
		const stranger = harness({ authenticated: false });
		expect(
			await stranger.send([
				["request", jar(claims())],
				["scope", "a"],
				["scope", "a"],
			]),
		).toMatchObject({ status: 400, json: { error_description: "repeated parameter" } });
		expect((await stranger.send({ request: jar(claims()) })).status).toBe(401);
	});

	it("serves the path the wire's par operation names", () => {
		expect(parPath).toBe(overHttp.operations.par.path);
	});
});

describe("the login's start by request_uri", () => {
	it("gives the pushing client its JAR, and refuses another client, an unknown or no such uri", async () => {
		const h = harness();
		const request = jar(claims());
		await h.send({ request });
		const source = pushedSource(h.store.pushed, true);
		const uri = `${requestUriPrefix}t1`;
		expect(await source.jarOf({ requestUri: uri }, client)).toEqual({ jar: request });
		expect(await source.jarOf({ requestUri: uri }, { ...client, id: "c2" })).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ requestUri: `${requestUriPrefix}none` }, client)).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ requestUri: "https://elsewhere" }, client)).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ request }, client)).toBeUndefined();
	});

	it("refuses, keeping nothing, a JAR that expired while its proof was checked", async () => {
		const h = harness({ proofMs: 61_000 });
		expect(await h.send({ request: jar(claims()) })).toMatchObject({
			status: 400,
			json: { error: "invalid_request_object", error_description: "the request has expired" },
		});
		expect(h.store.kept.size).toBe(0);
	});
});

describe("a pushed request checked by authorize's own check", () => {
	const registered = {
		...client,
		section: <T>(s: { name: string }) =>
			(s.name === redirects.name
				? { "redirect-uris": ["https://rp.example/cb"] }
				: { grants: ["authorization_code"], scopes: ["openid", "read"], audiences: [] }) as T,
	} as Client;
	const full = (more: Record<string, unknown> = {}) =>
		Object.fromEntries(
			Object.entries(
				claims({
					redirect_uri: "https://rp.example/cb",
					response_type: "code",
					response_mode: "form_post",
					state: "st",
					nonce: "n",
					scope: "openid read",
					code_challenge: "c".repeat(43),
					code_challenge_method: "S256",
					...more,
				}),
			).filter(([, v]) => v !== undefined),
		);
	const composed = (p: { idTokens?: boolean; grants?: string[] } = {}) =>
		harness({
			client:
				p.grants === undefined
					? registered
					: ({
							...registered,
							section: <T>(s: { name: string }) =>
								(s.name === redirects.name
									? registered.section<T>(s as never)
									: { grants: p.grants, scopes: ["openid", "read"], audiences: [] }) as T,
						} as Client),
			requests: (bindings) =>
				authorizationRequestsOf({
					bindings,
					issuer,
					...(p.idTokens === undefined ? {} : { idTokens: p.idTokens }),
				}),
		});

	it("takes a good request, and refuses each of the suite's kinds with its code, reading no proof and keeping nothing", async () => {
		expect(await composed().send({ request: jar(full()) })).toMatchObject({ status: 201 });
		const kinds: [
			string,
			Record<string, unknown>,
			string,
			{ idTokens?: boolean; grants?: string[] }?,
		][] = [
			["no state", { state: undefined }, "invalid_request"],
			["no nonce", { nonce: undefined }, "invalid_request"],
			["a state over its bound", { state: "s".repeat(513) }, "invalid_request"],
			["a nonce over its bound", { nonce: "n".repeat(513) }, "invalid_request"],
			["response_mode not form_post", { response_mode: "query" }, "invalid_request"],
			[
				"PKCE missing",
				{ code_challenge: undefined, code_challenge_method: undefined },
				"invalid_request",
			],
			["plain", { code_challenge_method: "plain" }, "invalid_request"],
			["code_challenge_method absent", { code_challenge_method: undefined }, "invalid_request"],
			["code_challenge_method unknown", { code_challenge_method: "S512" }, "invalid_request"],
			["a challenge malformed", { code_challenge: "short" }, "invalid_request"],
			["a claim outside the set", { other: 1 }, "invalid_request_object"],
			[
				"a request_uri in the JAR",
				{ request_uri: `${requestUriPrefix}x` },
				"invalid_request_object",
			],
			[
				"a redirect URI not registered",
				{ redirect_uri: "https://evil.example/cb" },
				"invalid_request",
			],
			["no redirect URI", { redirect_uri: undefined }, "invalid_request"],
			["prompt=none", { prompt: "none" }, "login_required"],
			["a prompt word not taken", { prompt: "create" }, "invalid_request"],
			["claims, none read here", { claims: { id_token: {} } }, "invalid_request_object"],
			["openid with no ID token", {}, "invalid_scope", { idTokens: false }],
			["a scope not allowed", { scope: "write" }, "invalid_scope"],
			["a resource, no rule reading it", { resource: "https://api" }, "invalid_target"],
			["a grant not allowed", {}, "unauthorized_client", { grants: [] }],
			["no dpop_jkt", { dpop_jkt: undefined }, "invalid_request"],
			["a dpop_jkt out of its form", { dpop_jkt: "bad" }, "invalid_request"],
		];
		for (const [kind, more, error, parts] of kinds) {
			const h = composed(parts);
			expect(await h.send({ request: jar(full(more)) }), kind).toMatchObject({
				status: 400,
				json: { error },
			});
			expect(h.proofs(), kind).toBe(0);
			expect(h.store.kept.size, kind).toBe(0);
		}
	});
});
