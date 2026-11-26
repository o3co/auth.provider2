import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { authMethods } from "@mod/clients";
import { type Grant, grants } from "@mod/grants";
import { assemble, BootRefused, defineModule } from "@mod/kernel";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { type IssuanceRequest, issuancePolicies } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { tokenEndpointLocation } from "../src/contract.ts";
import { answered, logged as book, endpointConfig, endpointModules } from "./deployment.ts";

import { claimsOf, client, echoClients, events, quiet, serve } from "./served.ts";

describe("the audience a request asks for", () => {
	it("refuses to boot with a grant that does not say what it reads that a browser sends by itself", async () => {
		const silent = defineModule({ name: "silent", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(
				() =>
					({
						grantType: "urn:test:silent",
						handle: async () => ({ kind: "issued", body: {} }),
					}) as unknown as Grant,
			),
		]);
		await expect(serve([silent])).rejects.toSatisfy(
			(error) =>
				error instanceof BootRefused &&
				error.refusals.some(
					(r) =>
						r.where === "grants:urn:test:silent" &&
						r.reason === "declares neither readsAmbient none nor cookie",
				),
		);
	});
});

describe("token endpoint", () => {
	it("issues client credentials tokens with basic and post, uncached by the no-store and no-cache http's jsonAnswer writes on each answer it builds, and with expires_in in every answer the client credentials grant gives, each grant writing its own [rfc6749-2.3.1-a] [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-3.3-a] [rfc6749-5.1-c] [rfc6749-5.1-d] [oidc-core-16.4-a]", async () => {
		const post = await serve();
		const basic = await post({ grant_type: "client_credentials", scope: "read write" }, "basic");
		expect(basic.status).toBe(200);
		expect(basic.headers.get("cache-control")).toBe("no-store");
		expect(basic.headers.get("pragma")).toBe("no-cache");
		expect(basic.body).toMatchObject({
			token_type: "Bearer",
			expires_in: 300,
			scope: "read write",
		});
		expect(claimsOf(basic.body)).toMatchObject({
			iss: "https://issuer.example",
			sub: "basic",
			client_id: "basic",
			aud: "https://api",
		});
		const viaPost = await post({
			grant_type: "client_credentials",
			client_id: "post",
			client_secret: "post-secret",
		});
		expect(viaPost.body).toMatchObject({ scope: "read" });
		expect([viaPost.headers.get("cache-control"), viaPost.headers.get("pragma")]).toEqual([
			"no-store",
			"no-cache",
		]);
		expect(typeof viaPost.body.expires_in).toBe("number");
	});

	it("issues a client's default scopes when none is asked, none when it has none, and refuses a client with no default [rfc6749-3.3-b]", async () => {
		const post = await serve();
		const noscope = await post({ grant_type: "client_credentials" }, "noscope");
		expect(noscope.status).toBe(200);
		expect(noscope.body.scope).toBeUndefined();
		const empty = await post({ grant_type: "client_credentials" }, "emptydefault");
		expect([empty.status, empty.body.scope]).toEqual([200, undefined]);
		expect((await post({ grant_type: "client_credentials" }, "nodefault")).body.error).toBe(
			"invalid_scope",
		);
	});

	it("lets a listed origin's page send a body's type and its DPoP proof, and read the nonce, the challenge and the wait [oidc-discovery-3-aj]", async () => {
		const post = await serve([], { peer: { "cors-origins": ["https://app.example"] } });
		const origin = "https://app.example";
		const preflight = await fetch(post.url, {
			method: "OPTIONS",
			headers: {
				origin,
				"access-control-request-method": "POST",
				"access-control-request-headers": "content-type, dpop",
			},
		});
		expect(preflight.headers.get("access-control-allow-origin")).toBe(origin);
		const allowed = (preflight.headers.get("access-control-allow-headers") ?? "").toLowerCase();
		for (const name of ["content-type", "dpop"]) expect(allowed).toContain(name);
		const answered = await fetch(post.url, {
			method: "POST",
			headers: { origin, "content-type": "application/x-www-form-urlencoded" },
			body: "grant_type=client_credentials&client_id=pub",
		});
		expect(answered.headers.get("access-control-allow-origin")).toBe(origin);
		expect(
			answered.headers.get("access-control-expose-headers")?.toLowerCase().split(/,\s*/),
		).toEqual(expect.arrayContaining(["dpop-nonce", "www-authenticate", "retry-after"]));
	});

	it("limits requests per source before any client is authenticated, answering 429 rate_limited from the rate-limit policy before the endpoint, bound to no token type, parameter or grant (as its 503 when it cannot count), the codes its grants answer being registered [rfc6749-2.3.1-c] [guarantee-10-a] [rfc6749-8.5-a]", async () => {
		let handled = 0;
		const counting = defineModule({ name: "counting", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => {
					handled += 1;
					return { kind: "error", error: "invalid_grant" };
				},
			})),
		]);
		const post = await serve([counting], {
			settings: { requests: 2, window: "2m" },
			clients: [echoClients.echo()],
		});
		const wrong = () => post({ grant_type: "client_credentials" }, "basic", { secret: "wrong" });
		expect([(await wrong()).status, (await wrong()).status]).toEqual([401, 401]);
		const before = events.length;
		const limited = await post({ grant_type: "urn:test:echo" }, "echo");
		expect([limited.status, limited.headers.get("retry-after"), limited.body]).toEqual([
			429,
			"120",
			{ error: "rate_limited" },
		]);
		// Answered before the endpoint: no grant ran, and no grant's issuance or refusal was recorded.
		expect(handled).toBe(0);
		expect(events.slice(before).filter((e) => e.kind.startsWith("token."))).toEqual([]);
	});

	it("hands a grant what its client's authentication verified, unread, and none for another method", async () => {
		const proof = { key: "verified" };
		const proving = defineModule({ name: "proving", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(authMethods).by(() => ({
				name: "proving",
				claimed: (r) => r.form.get("proving_id")?.[0],
				verify: async () => ({ proof }),
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) =>
					answered(input, {
						authenticated: input.authenticated === proof ? "same" : String(input.authenticated),
					}),
			})),
		]);
		const proved = client("proved", "proving", { grants: ["urn:test:echo"] });
		const post = await serve([proving], { clients: [proved, echoClients.echo()] });
		const by = await post({ grant_type: "urn:test:echo", proving_id: "proved" });
		expect(by.body).toEqual({ authenticated: "same" });
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body).toEqual({
			authenticated: "undefined",
		});
		// A method that is no assertion's verified no assertion sent beside its credentials: none is recorded as evidence.
		const before = book?.sent.length ?? 0;
		const beside = { grant_type: "urn:test:echo", proving_id: "proved", client_assertion: "a.b.c" };
		expect((await post(beside)).body).toEqual({ authenticated: "same" });
		const starts = book?.sent.slice(before).filter((s) => s.stage.stage === 1);
		expect(starts?.map((s) => s.stage.preimage.evidence)).toEqual([[]]);
	});

	it("answers each refusal with its OAuth error, authenticating the client by clients' authenticate, which every endpoint authenticating a client calls, each code a fixed word within the error ABNF as every endpoint's is, the password grant not offered [rfc6749-5.2-b] [rfc6749-3.2.1-a] [rfc6749-4.4-a] [rfc6749-4.4.2-a] [rfc6749-10.2-a] [oidc-core-16.8-a] [rfc6749-5.2-c] [rfc6749-8.5-b] [rfc9700-2.4-a]", async () => {
		const post = await serve();
		const cc = { grant_type: "client_credentials" };
		const wrong = await post(cc, "basic", { secret: "nope" });
		expect([
			wrong.status,
			wrong.body.error,
			wrong.headers.get("www-authenticate")?.startsWith("Basic"),
		]).toEqual([401, "invalid_client", true]);
		expect((await post(cc)).status, "no client").toBe(401);
		expect((await post(cc, "nogrant")).body.error, "grant not allowed").toBe("unauthorized_client");
		expect((await post({ ...cc, scope: "admin" }, "basic")).body.error, "scope not allowed").toBe(
			"invalid_scope",
		);
		expect((await post({ grant_type: "foo" }, "basic")).body.error, "unknown grant type").toBe(
			"unsupported_grant_type",
		);
		expect((await post({}, "basic")).body.error, "no grant_type").toBe("invalid_request");
		expect((await post({ ...cc, client_id: "pub" })).body.error, "public client").toBe(
			"unauthorized_client",
		);
		const password = await post(
			{ grant_type: "password", username: "alice", password: "pw" },
			"basic",
		);
		expect(password.body.error, "the password grant").toBe("unsupported_grant_type");
		// Every code the endpoint answers keeps to RFC 6749's NQSCHAR, quote and backslash excepted.
		const answered = [
			wrong,
			await post(cc),
			await post(cc, "nogrant"),
			await post({ ...cc, scope: "admin" }, "basic"),
			await post({ grant_type: "foo" }, "basic"),
			await post({}, "basic"),
			password,
		].map((answer) => String(answer.body.error));
		for (const error of answered) expect(error).toMatch(/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/);
	});

	it("never records a proxy's address as the source: the limit answers an undetermined sender first [guarantee-10-a]", async () => {
		const post = await serve([], { peer: { "trusted-proxies": ["127.0.0.1"] } });
		const res = await post({ grant_type: "client_credentials" }, "basic");
		expect([res.status, events]).toEqual([503, []]);
	});

	it("admits and issues through the issuance policies under the grant type and the session, answering a refusal from admits or from issue as invalid_grant, auditing the policy but no value", async () => {
		const asked: IssuanceRequest[] = [];
		const policed = defineModule({ name: "policed", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, admits, issue }) => {
					const subject = param("subject") ?? "s";
					const session = param("session");
					const from = session === undefined ? {} : { session };
					const grant = {
						subject,
						subjectKind: "user" as const,
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
					};
					const admitted = await admits(grant, from);
					if (admitted.kind === "refused") return admitted;
					const issued = await issue({ access: grant }, { ...from, notAfter: 1_800_000_060_000 });
					if (issued.kind === "refused") return issued;
					return {
						kind: "issued",
						body: { token_type: issued.access.tokenType, expires_in: issued.access.expiresIn },
					};
				},
			})),
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					// "late" is admitted, then refused when issued.
					const late = asked.filter(({ grant }) => grant.subject === "late").length === 2;
					return request.grant.subject === "unwelcome" || late
						? { kind: "refused", reason: "test_reason", description: "not for this subject" }
						: { kind: "allowed" };
				},
			})),
		]);
		const post = await serve([policed], { clients: [echoClients.echo()] });
		const issued = await post({ grant_type: "urn:test:echo", session: "sid" }, "echo");
		expect([issued.status, issued.body]).toEqual([200, { token_type: "Bearer", expires_in: 60 }]);
		// The grant's admits, then the bundle's before its start is recorded, then tokens' prepare.
		expect(asked.map(({ grantType, session }) => ({ grantType, session }))).toEqual([
			{ grantType: "urn:test:echo", session: "sid" },
			{ grantType: "urn:test:echo", session: "sid" },
			{ grantType: "urn:test:echo", session: "sid" },
		]);
		const refusal = [400, { error: "invalid_grant", error_description: "not for this subject" }];
		for (const subject of ["unwelcome", "late"]) {
			const before = events.length;
			const refused = await post({ grant_type: "urn:test:echo", subject }, "echo");
			expect([refused.status, refused.body]).toEqual(refusal);
			expect(events.slice(before)).toEqual([
				{
					kind: "token.issued.failure",
					at: 1_800_000_000_000,
					attributes: {
						client: "echo",
						source: "127.0.0.1",
						grant_type: "urn:test:echo",
						reason: "issuance_refused",
						error: "invalid_grant",
						policy: "test-policy",
						refusal: "test_reason",
					},
				},
			]);
		}
		expect(asked.map(({ grant }) => grant.subject)).toEqual([
			"s",
			"s",
			"s",
			"unwelcome",
			"late",
			"late",
		]);
		expect(JSON.stringify(events)).not.toMatch(/unwelcome|late|not for this subject/);
	});

	it("tells the issuance policies an issuance continues a grant only when the grant says so", async () => {
		const seen: unknown[] = [];
		const continuing = defineModule({ name: "continuing", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, admits, issue }) => {
					const from = param("continuing") === "yes" ? { continuing: true as const } : {};
					const grant = {
						subject: "s",
						subjectKind: "user" as const,
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
					};
					const admitted = await admits(grant, from);
					if (admitted.kind === "refused") return admitted;
					const issued = await issue({ access: grant }, from);
					if (issued.kind === "refused") return issued;
					return { kind: "issued", body: {} };
				},
			})),
			m.contribute(issuancePolicies).by(() => ({
				name: "watching",
				judge: async (request) => {
					seen.push(request.continuing);
					return { kind: "allowed" };
				},
			})),
		]);
		const post = await serve([continuing], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", continuing: "yes" }, "echo")).status).toBe(
			200,
		);
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		// Each asked by the grant's admits, the bundle's and tokens' prepare.
		expect(seen).toEqual([true, true, true, undefined, undefined, undefined]);
	});

	it("tells where it answers, on the public origin whatever path the issuer has", async () => {
		const at = async (origin: string) => {
			const app = await assemble({
				modules: endpointModules(clientAllowanceModule, rateLimitStandIn, auditStandIn().module),
				config: {
					...endpointConfig({ peer: { "public-origin": origin }, issuer: `${origin}/tenant` }),
				},
				runtime: quiet,
			});
			return app.get(tokenEndpointLocation).url;
		};
		expect(await at("https://as.example")).toBe("https://as.example/oauth/token");
	});

	it("answers a grant's error with its status and members, never letting members replace the error [rfc6749-5.2-d]", async () => {
		const owned = defineModule({ name: "owned", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ param }) =>
					param("answer") === "none"
						? {
								kind: "error",
								error: "unauthorized",
								status: 401,
								members: { error_description: "\u0001" },
							}
						: {
								kind: "error",
								error: "invalid_grant",
								description: 'stronger "login" needed',
								members: { step_up: ["mfa"], error: "other", error_description: "other" },
							},
			})),
		]);
		const post = await serve([owned], { clients: [echoClients.echo()] });
		const none = await post({ grant_type: "urn:test:echo", answer: "none" }, "echo");
		expect([none.status, none.body]).toEqual([401, { error: "unauthorized" }]);
		const stepUp = await post({ grant_type: "urn:test:echo" }, "echo");
		expect([stepUp.status, stepUp.body]).toEqual([
			400,
			// A description holds printable ASCII but `"` and `\` (RFC 6749 §5.2).
			{ step_up: ["mfa"], error: "invalid_grant", error_description: "stronger ?login? needed" },
		]);
		expect(events.map((e) => e.attributes?.error)).toEqual(["unauthorized", "invalid_grant"]);
	});

	it("drops what a grant's error may not carry: a success's or the error's members, an error_uri that is not a printable URI, a status but 400 or 401 [rfc6749-5.2-e] [rfc6749-5.2-a]", async () => {
		const loose = defineModule({ name: "loose", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["json"],
				handle: async ({ value }) => ({
					kind: "error",
					error: String(value("error")),
					status: value("status") as 400,
					members: value("members") as Record<string, unknown>,
				}),
			})),
		]);
		const post = await serve([loose], { clients: [echoClients.echo()] });
		const answered = async (error: string, members: Record<string, unknown>, status?: number) => {
			const res = await post({ grant_type: "urn:test:echo", error, members, status }, "echo", {
				as: "json",
			});
			return [res.status, res.body];
		};
		const success = {
			access_token: "t",
			token_type: "Bearer",
			expires_in: 1,
			refresh_token: "r",
			scope: "read",
		};
		const own = { error: "other", error_description: "other" };
		expect(await answered("invalid_grant", { ...success, ...own, kept: 1 })).toEqual([
			400,
			{ kept: 1, error: "invalid_grant" },
		]);
		for (const uri of [
			"https://e.example/a b",
			'https://e.example/"',
			"https://e.example/\u00e9",
			"doc",
			1,
		]) {
			expect(await answered("invalid_grant", { error_uri: uri })).toEqual([
				400,
				{ error: "invalid_grant" },
			]);
		}
		const uri = "https://e.example/doc?x=1#y";
		expect(await answered("invalid_grant", { error_uri: uri })).toEqual([
			400,
			{ error_uri: uri, error: "invalid_grant" },
		]);
		expect((await answered("invalid_grant", {}, 200))[0]).toBe(400);
		expect((await answered("invalid_grant", {}, 503))[0]).toBe(400);
		expect((await answered("invalid_client", {}, 500))[0]).toBe(401);
	});

	it("takes a JSON body only for a grant that declares it, and a form only for one that does; another type is 415, and an empty form names no grant", async () => {
		const declared = defineModule({ name: "declared", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["json"],
				handle: async ({ param, value, ...input }) =>
					answered(input, {
						scope: param("scope") ?? "absent",
						assertion: value("assertion") ?? "absent",
					}),
			})),
		]);
		const post = await serve([declared], { clients: [echoClients.echo()] });
		const echo = { grant_type: "urn:test:echo", scope: "read", assertion: { id: "a", n: [1] } };
		const json = await post(echo, "echo", { as: "json" });
		expect([json.status, json.body]).toEqual([
			200,
			{ scope: "read", assertion: { id: "a", n: [1] } },
		]);
		const form = await post({ grant_type: "urn:test:echo", scope: "read" }, "echo");
		expect([form.status, form.body.error]).toEqual([400, "invalid_request"]);
		const cc = await post({ grant_type: "client_credentials" }, "basic", { as: "json" });
		expect([cc.status, cc.body.error]).toEqual([400, "invalid_request"]);
		// After the JSON grant's issuance, each body a grant does not take is a refusal recorded.
		expect(events.slice(1).map((e) => e.attributes)).toEqual([
			{
				client: "echo",
				source: "127.0.0.1",
				grant_type: "urn:test:echo",
				reason: "unsupported_body",
				error: "invalid_request",
			},
			{
				client: "basic",
				source: "127.0.0.1",
				grant_type: "client_credentials",
				reason: "unsupported_body",
				error: "invalid_request",
			},
		]);
		const text = await post({ grant_type: "client_credentials" }, "basic", { as: "text" });
		expect(text.status).toBe(415);
		// An empty form is checked as any other, and names no grant_type.
		expect((await post({}, "basic")).body.error_description).toBe("grant_type is required");
	});
});
