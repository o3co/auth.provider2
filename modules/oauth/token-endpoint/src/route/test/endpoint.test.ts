import { type Grant, grants } from "@mod/grants";
import { defineModule, Unavailable } from "@mod/kernel";
import { senderBindings } from "@mod/sender-binding";
import type { AddedClaims } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { answered } from "../../../test/deployment.ts";
import {
	audienceOf,
	claimsOf,
	client,
	echoClients,
	events,
	logged,
	narrowing,
	quiet,
	serve,
	stop,
} from "../../../test/served.ts";

describe("the audience a request asks for", () => {
	it("narrows client credentials by the composed rule, within what the client may be issued [oidc-core-16.8-a]", async () => {
		const post = await serve([narrowing("strict", true)]);
		const asked = (resource?: string) =>
			post({ grant_type: "client_credentials", ...(resource ? { resource } : {}) }, "narrow");
		expect(audienceOf((await asked("https://two")).body)).toBe("https://two");
		expect(audienceOf((await asked()).body)).toBe("https://api");
		expect((await asked("https://elsewhere")).body).toEqual({
			error: "invalid_target",
			error_description: "not https://elsewhere",
		});
	});

	it("answers a grant another module contributes, as token exchange is, by the same no-store answer as its own [oidc-core-16.4-a]", async () => {
		const exchanging = defineModule({ name: "exchanging", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, issue }) => {
					const access = {
						subject: client.id,
						subjectKind: "user" as const,
						issuedTo: client.id,
					};
					const issued = await issue({ access: { ...access, audience: [], scope: [] } });
					if (issued.kind !== "issued") return issued;
					const body = { access_token: issued.access.token, token_type: "Bearer" };
					return { kind: "issued", body };
				},
			})),
		]);
		const post = await serve([exchanging], { clients: [echoClients.echo()] });
		const answer = await post({ grant_type: "urn:test:echo" }, "echo");
		expect([answer.status, typeof answer.body.access_token]).toEqual([200, "string"]);
		expect([answer.headers.get("cache-control"), answer.headers.get("pragma")]).toEqual([
			"no-store",
			"no-cache",
		]);
	});

	it("refuses, before the grant runs, an audience asked of a grant that takes none, where the rule says so", async () => {
		const handled: string[] = [];
		const echoes = defineModule({ name: "echoes", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => {
					handled.push("echo");
					return answered(input, { by: "echo" });
				},
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:other",
				readsAmbient: "none",
				targets: true,
				handle: async (input) => {
					handled.push("other");
					return answered(input, { by: "other" });
				},
			})),
		]);
		const post = await serve([echoes, narrowing("strict", true)], {
			clients: [echoClients.echoes()],
		});
		const resource = "https://two";
		expect((await post({ grant_type: "urn:test:echo", resource }, "echoes")).body).toEqual({
			error: "invalid_target",
			error_description: "no resource here",
		});
		expect(handled).toEqual([]);
		expect(events.at(-1)).toMatchObject({
			kind: "token.issued.failure",
			attributes: { grant_type: "urn:test:echo", reason: "untargeted", error: "invalid_target" },
		});
		expect((await post({ grant_type: "urn:test:echo" }, "echoes")).body).toEqual({ by: "echo" });
		expect((await post({ grant_type: "urn:test:other", resource }, "echoes")).body).toEqual({
			by: "other",
		});
		expect(handled).toEqual(["echo", "other"]);
	});

	it("answers a parameter the rule reads sent twice as the rule says, and any other as a malformed request [rfc6749-3.2-d]", async () => {
		const twice = new URLSearchParams([
			["grant_type", "client_credentials"],
			["resource", "https://two"],
			["resource", "https://api"],
		]);
		const strict = await serve([narrowing("strict", true)]);
		expect((await strict(twice, "narrow")).body).toEqual({
			error: "invalid_target",
			error_description: "one resource",
		});
		expect(events.at(-1)).toMatchObject({
			attributes: { reason: "repeated_parameter", error: "invalid_target" },
		});
		const scopes = new URLSearchParams([
			["grant_type", "client_credentials"],
			["scope", "read"],
			["scope", "write"],
		]);
		expect((await strict(scopes, "narrow")).body).toMatchObject({ error: "invalid_request" });
		await stop();
		const plain = await serve([narrowing()]);
		expect((await plain(twice, "narrow")).body).toMatchObject({ error: "invalid_request" });
	});

	it("leaves an audience asked of a grant that takes none to the grant where the rule says nothing of it", async () => {
		const echo = defineModule({ name: "echo", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => answered(input, { by: "echo" }),
			})),
		]);
		const post = await serve([echo, narrowing()], { clients: [echoClients.echo()] });
		expect(
			(await post({ grant_type: "urn:test:echo", resource: "https://two" }, "echo")).body,
		).toEqual({ by: "echo" });
	});
});

describe("token endpoint", () => {
	it("passes over the parameters it does not recognize, issuing as without them [rfc6749-3.2-c]", async () => {
		const post = await serve();
		const issued = await post(
			{ grant_type: "client_credentials", ui_locales: "fr", x_vendor: "1", audience: "x" },
			"basic",
		);
		expect([issued.status, issued.body.token_type]).toEqual([200, "Bearer"]);
		expect(claimsOf(issued.body)).toMatchObject({ sub: "basic", aud: "https://api" });
	});

	it("refuses authorization_details on every grant, before the grant runs, as PAR does (A25: rich authorization requests are not taken)", async () => {
		const post = await serve();
		for (const grant_type of ["client_credentials", "authorization_code", "refresh_token"]) {
			const refused = await post({ grant_type, authorization_details: '[{"type":"x"}]' }, "basic");
			expect([refused.status, refused.body]).toEqual([
				400,
				{ error: "invalid_request", error_description: "authorization_details are not taken" },
			]);
			expect(events.at(-1)).toMatchObject({
				attributes: { reason: "authorization_details", error: "invalid_request" },
			});
		}
		// Sent empty, it is sent: a request carrying the parameter at all is refused.
		expect(
			(await post({ grant_type: "client_credentials", authorization_details: "" }, "basic")).body,
		).toEqual({
			error: "invalid_request",
			error_description: "authorization_details are not taken",
		});
		// In JSON, of any type but null, which is as if left out.
		for (const authorization_details of [[{ type: "x" }], {}, "x", 1, false]) {
			const json = await post(
				{ grant_type: "client_credentials", authorization_details },
				"basic",
				{
					as: "json",
				},
			);
			expect(json.body, JSON.stringify(authorization_details)).toMatchObject({
				error_description: "authorization_details are not taken",
			});
		}
		// Null is as if left out: whatever refuses the request next, it is not this.
		const leftOut = { grant_type: "client_credentials", authorization_details: null };
		const nulled = await post(leftOut, "basic", { as: "json" });
		expect(nulled.body.error_description).not.toBe("authorization_details are not taken");
		expect(events.at(-1)?.attributes).not.toMatchObject({ reason: "authorization_details" });
		// Sent twice, it is a repeated parameter first.
		const twice = new URLSearchParams([
			["grant_type", "client_credentials"],
			["authorization_details", "[]"],
			["authorization_details", "[]"],
		]);
		expect((await post(twice, "basic")).body).toEqual({
			error: "invalid_request",
			error_description: "repeated parameter",
		});
		expect(events.at(-1)).toMatchObject({ attributes: { reason: "repeated_parameter" } });
		// Without it, the same client is issued.
		expect((await post({ grant_type: "client_credentials" }, "basic")).status).toBe(200);
	});

	it("refuses a client that must bind and shows no binding, or one of a kind it does not name, before the grant runs", async () => {
		let ran = 0;
		const kinds = defineModule({ name: "kinds", replicaSafe: false, takes: [] }, (m) => [
			...(
				[
					["one", "first"],
					["two", "second"],
				] as const
			).map(([name, field]) =>
				m.contribute(senderBindings).by(() => ({
					member: `m-${name}`,
					name,
					tokenType: "Test",
					read: async (request) =>
						request.form.has(field)
							? ({ kind: "bound", confirmation: "k" } as const)
							: ({ kind: "absent" } as const),
				})),
			),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => {
					ran++;
					return answered(input, {});
				},
			})),
		]);
		const grantsEcho = { grants: ["urn:test:echo"] };
		const post = await serve([kinds], {
			clients: [
				client("must", "client_secret_basic", grantsEcho, { "sender-binding": { required: true } }),
				client("oneonly", "client_secret_basic", grantsEcho, {
					"sender-binding": { kinds: ["one"] },
				}),
			],
		});
		const echo = { grant_type: "urn:test:echo" };
		const unbound = await post(echo, "must");
		expect([unbound.status, unbound.body.error]).toEqual([400, "invalid_request"]);
		const other = await post({ ...echo, second: "1" }, "oneonly");
		expect([other.status, other.body.error]).toEqual([400, "unauthorized_client"]);
		expect(ran).toBe(0);
		expect(events.map((e) => e.attributes?.reason)).toEqual([
			"binding_required",
			"binding_kind_not_named",
		]);
		expect((await post({ ...echo, first: "1" }, "must")).status).toBe(200);
		expect((await post({ ...echo, first: "1" }, "oneonly")).status).toBe(200);
		expect((await post(echo, "oneonly")).status).toBe(200);
		expect(ran).toBe(3);
	});

	it("names the claims a grant added to the tokens it issued, never their values, in the order of their names", async () => {
		const claimed = (name: string, sets: readonly AddedClaims[]) =>
			defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: name === "twice" ? "urn:test:echo" : "urn:test:other",
					readsAmbient: "none",
					handle: async (input) => {
						for (const claims of sets) {
							const base = {
								subject: "sue",
								subjectKind: "user" as const,
								issuedTo: input.client.id,
								audience: [],
								scope: [],
							};
							const grant = Object.keys(claims).length > 0 ? { ...base, claims } : base;
							const issued = await input.issue({ access: grant });
							if (issued.kind !== "issued") return { kind: "refused", refusal: issued.refusal };
						}
						return { kind: "issued", body: {} };
					},
				})),
			]);
		const post = await serve(
			[
				claimed("twice", [{ "zeta.example": "z-value", "alpha.example": 1, "mid.example": true }]),
				claimed("none", [{}]),
			],
			{ clients: [echoClients.echoes()] },
		);
		expect((await post({ grant_type: "urn:test:echo" }, "echoes")).status).toBe(200);
		expect(events.at(-1)).toMatchObject({
			kind: "token.issued",
			attributes: { claims: "alpha.example mid.example zeta.example" },
		});
		expect(JSON.stringify(events.at(-1))).not.toContain("z-value");
		expect((await post({ grant_type: "urn:test:other" }, "echoes")).status).toBe(200);
		expect(events.at(-1)?.attributes).not.toHaveProperty("claims");
	});

	it("names every added claim while they fit in 2048 characters, else as many as fit and how many it left out", async () => {
		const named = (length: number, count: number) =>
			Object.fromEntries(
				Array.from({ length: count }, (_, i) => [
					`${String(i).padStart(2, "0")}${"n".repeat(length - 2)}`,
					0,
				]),
			);
		const issuing = (claims: Record<string, number>) =>
			defineModule({ name: "many", replicaSafe: true, takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: "urn:test:echo",
					readsAmbient: "none",
					handle: async (input) => {
						const base = {
							subject: "sue",
							subjectKind: "user" as const,
							issuedTo: input.client.id,
							audience: [],
							scope: [],
						};
						const issued = await input.issue({ access: { ...base, claims } });
						return issued.kind === "issued"
							? { kind: "issued", body: {} }
							: { kind: "refused", refusal: issued.refusal };
					},
				})),
			]);
		// Eight names of 255 characters fill 2047, one space apart: all are named.
		const fits = await serve([issuing(named(255, 8))], { clients: [echoClients.echo()] });
		expect((await fits({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const all = events.at(-1)?.attributes;
		expect([String(all?.claims).split(" ").length, all?.claims_left]).toEqual([8, undefined]);
		await stop();
		// Twelve of 200: ten fit, and two are left out.
		const over = await serve([issuing(named(200, 12))], { clients: [echoClients.echo()] });
		expect((await over({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const cut = events.at(-1)?.attributes;
		expect([String(cut?.claims).length <= 2048, String(cut?.claims).split(" ").length]).toEqual([
			true,
			10,
		]);
		expect(cut?.claims_left).toBe("2");
	});

	it("names all at exactly 2048 characters, and leaves one out at 2049", async () => {
		/** Eight names of 227 characters and one of `last`, sorted by their first two digits. */
		const names = (last: number) =>
			Object.fromEntries(
				Array.from({ length: 9 }, (_, i) => {
					const length = i === 8 ? last : 227;
					return [`${String(i).padStart(2, "0")}${"n".repeat(length - 2)}`, 0];
				}),
			);
		const issuing = (claims: Record<string, number>) =>
			defineModule({ name: "edge", replicaSafe: true, takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: "urn:test:echo",
					readsAmbient: "none",
					handle: async (input) => {
						const base = {
							subject: "sue",
							subjectKind: "user" as const,
							issuedTo: input.client.id,
							audience: [],
							scope: [],
						};
						const issued = await input.issue({ access: { ...base, claims } });
						return issued.kind === "issued"
							? { kind: "issued", body: {} }
							: { kind: "refused", refusal: issued.refusal };
					},
				})),
			]);
		// 8 × 227 + 8 spaces + 224 = 2048.
		const exact = await serve([issuing(names(224))], { clients: [echoClients.echo()] });
		expect((await exact({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const all = events.at(-1)?.attributes;
		expect([String(all?.claims).length, all?.claims_left]).toEqual([2048, undefined]);
		await stop();
		const over = await serve([issuing(names(225))], { clients: [echoClients.echo()] });
		expect((await over({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const cut = events.at(-1)?.attributes;
		expect([String(cut?.claims).split(" ").length, cut?.claims_left]).toEqual([8, "1"]);
	});

	it("records each issuance and each refusal it decides, with the client and the source, never a token or secret [oidc-core-16.4-a]", async () => {
		const polled = defineModule({ name: "polled", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => ({ kind: "error", error: "authorization_pending" }),
			})),
			m.contribute(senderBindings).by(() => ({
				member: "test",
				tokenType: "Test",
				read: async (request) => {
					if (request.form.has("down")) {
						const headers = { "retry-after": "1" };
						return { kind: "refused", error: "test_down", unavailable: true, headers };
					}
					return request.form.has("bind")
						? { kind: "refused", error: "invalid_test_proof" }
						: { kind: "absent" };
				},
			})),
		]);
		const post = await serve([polled], { clients: [echoClients.echo()] });
		const cc = { grant_type: "client_credentials" };
		const issued = await post(cc, "basic");
		expect(issued.status).toBe(200);
		// Refused before the client is known: the authentication's failure, naming no client.
		await post(cc, "basic", { secret: "nope" });
		// A grant type nothing dispatches to is recorded without its name.
		await post({ grant_type: "foo" }, "basic");
		await post({}, "basic");
		await post(cc, "nogrant");
		await post({ ...cc, scope: "admin" }, "basic");
		await post({ ...cc, bind: "1" }, "basic");
		// A binding that cannot tell is 503 with its headers, and not recorded.
		const down = await post({ ...cc, down: "1" }, "basic");
		expect([down.status, down.body.error, down.headers.get("retry-after")]).toEqual([
			503,
			"test_down",
			"1",
		]);
		await post({ grant_type: "urn:test:echo" }, "echo");
		const at = quiet.clock.now();
		const source = "127.0.0.1";
		const failed = (client: string, attributes: Record<string, string>) => ({
			kind: "token.issued.failure",
			at,
			attributes: { client, source, ...attributes },
		});
		expect(events).toEqual([
			{ kind: "token.issued", at, attributes: { client: "basic", source, ...cc } },
			{
				kind: "client.authentication.failure",
				at,
				attributes: { source, reason: "bad_credentials" },
			},
			failed("basic", { reason: "unsupported_grant_type", error: "unsupported_grant_type" }),
			failed("basic", { reason: "missing_grant_type", error: "invalid_request" }),
			failed("nogrant", { ...cc, reason: "grant_type_not_allowed", error: "unauthorized_client" }),
			failed("basic", { ...cc, reason: "grant_refused", error: "invalid_scope" }),
			failed("basic", { ...cc, reason: "binding_refused", error: "invalid_test_proof" }),
			failed("echo", {
				grant_type: "urn:test:echo",
				reason: "grant_refused",
				error: "authorization_pending",
			}),
		]);
		expect(JSON.stringify(events)).not.toMatch(/secret|nope|foo/);
		// The token issued is in no event.
		expect(typeof issued.body.access_token).toBe("string");
		expect(JSON.stringify(events)).not.toContain(String(issued.body.access_token));
	});

	it("answers a grant that cannot tell with 503 temporarily_unavailable, unaudited, logging what and the grant type", async () => {
		const down = defineModule({ name: "down", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => {
					throw new Unavailable("test");
				},
			})),
		]);
		const post = await serve([down], { clients: [echoClients.echo()] });
		const before = logged.lines().length;
		const res = await post({ grant_type: "urn:test:echo", scope: "kept-out" }, "echo");
		expect([res.status, res.body, events]).toEqual([503, { error: "temporarily_unavailable" }, []]);
		expect(logged.lines().slice(before)).toEqual([
			{
				level: "warn",
				event: "http.unavailable",
				fields: { what: "test", route: "/oauth/token", grant_type: "urn:test:echo" },
			},
		]);
	});

	it("dispatches to a grant contributed from outside, for the clients whose allowance lists it", async () => {
		const extra = defineModule({ name: "extra-grant", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => answered(input, { echo: input.client.id }),
			})),
		]);
		const post = await serve([extra], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body).toEqual({ echo: "echo" });
		expect((await post({ grant_type: "urn:test:echo" }, "basic")).body.error).toBe(
			"unauthorized_client",
		);
	});

	it("answers an error code a grant owns as 400, as the grant names it", async () => {
		const polled = defineModule({ name: "polled", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ param }) => ({ kind: "error", error: param("answer") ?? "" }),
			})),
		]);
		const post = await serve([polled], { clients: [echoClients.echo()] });
		for (const answer of ["authorization_pending", "slow_down", "owned_by_the_grant"]) {
			const res = await post({ grant_type: "urn:test:echo", answer }, "echo");
			expect([res.status, res.body.error]).toEqual([400, answer]);
		}
	});

	it("challenges a grant's 401 with the client's method, or with every method when it has none", async () => {
		const unauthorized = defineModule(
			{ name: "unauthorized", replicaSafe: true, takes: [] },
			(m) => [
				m.contribute(grants).by(() => ({
					grantType: "urn:test:echo",
					readsAmbient: "none",
					handle: async ({ param }) => ({
						kind: "error",
						error: "invalid_client",
						status: param("status") === "400" ? 400 : 401,
					}),
				})),
			],
		);
		const post = await serve([unauthorized], {
			clients: [echoClients.echo(), echoClients.pubecho()],
		});
		const echo = { grant_type: "urn:test:echo" };
		const challenge = async (form: Record<string, string>, id?: string) => {
			const res = await post(form, id);
			return [res.status, res.headers.get("www-authenticate")];
		};
		expect(await challenge(echo, "echo")).toEqual([401, 'Basic realm="client"']);
		expect(await challenge({ ...echo, client_id: "pubecho" })).toEqual([
			401,
			'Basic realm="client"',
		]);
		expect(await challenge({ ...echo, status: "400" }, "echo")).toEqual([400, null]);
	});

	it("gives a grant that takes both bodies each one's values, a form's as single strings [rfc6749-3.2-d]", async () => {
		const both = defineModule({ name: "both", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["form", "json"],
				handle: async ({ param, value, ...input }) =>
					answered(input, {
						n: param("n") ?? "absent",
						value: value("n") ?? "absent",
						absent: value("x") ?? "absent",
					}),
			})),
		]);
		const post = await serve([both], { clients: [echoClients.echo()] });
		const form = await post({ grant_type: "urn:test:echo", n: "1" }, "echo");
		expect(form.body).toEqual({ n: "1", value: "1", absent: "absent" });
		const json = await post({ grant_type: "urn:test:echo", n: 1 }, "echo", { as: "json" });
		expect(json.body).toEqual({ n: "absent", value: 1, absent: "absent" });
		const repeated = await post(new URLSearchParams("grant_type=urn:test:echo&n=1&n=2"), "echo");
		expect([repeated.status, repeated.body.error]).toEqual([400, "invalid_request"]);
	});

	it("refuses an OAuth parameter sent in JSON as other than a string for every grant, null being left out", async () => {
		const echoing = (grantType: string, bodies: Grant["bodies"]): Grant => ({
			grantType,
			readsAmbient: "none",
			...(bodies ? { bodies } : {}),
			handle: async ({ param, value, ...input }) =>
				answered(input, {
					scope: param("scope") ?? "absent",
					assertion: value("assertion") ?? "absent",
				}),
		});
		const echoes = defineModule({ name: "echoes", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => echoing("urn:test:echo", ["json"])),
			m.contribute(grants).by(() => echoing("urn:test:other", ["form", "json"])),
		]);
		const post = await serve([echoes], { clients: [echoClients.echoes()] });
		const mistyped = [
			["scope", ["admin"]],
			["code", 1],
			["redirect_uri", { uri: "https://app.example/cb" }],
			["refresh_token", ["a", "b"]],
			["audience", ["https://api"]],
			["resource", true],
			["subject_token", 0],
			["client_secret", false],
		] as const;
		for (const grantType of ["urn:test:echo", "urn:test:other"]) {
			const sent = (members: Record<string, unknown>) =>
				post({ grant_type: grantType, ...members }, "echoes", { as: "json" });
			for (const [name, given] of mistyped) {
				const res = await sent({ [name]: given });
				expect([name, res.status, res.body.error]).toEqual([name, 400, "invalid_request"]);
			}
			const left = await sent({ scope: null, assertion: { id: "a" } });
			expect([left.status, left.body]).toEqual([200, { scope: "absent", assertion: { id: "a" } }]);
		}
		const typed = await post({ grant_type: ["urn:test:echo"] }, "echoes", { as: "json" });
		expect([typed.status, typed.body.error]).toEqual([400, "invalid_request"]);
		const reasons = events.filter((e) => e.kind === "token.issued.failure");
		expect(new Set(reasons.map((e) => e.attributes?.reason))).toEqual(
			new Set(["mistyped_parameter"]),
		);
		// A mistyped client_secret is refused by client authentication before this check.
		const authenticated = mistyped.filter(([name]) => name !== "client_secret");
		expect(reasons).toHaveLength(authenticated.length * 2 + 1);
	});

	it("gives a grant the binding its tokens carry, and none when the request has none", async () => {
		const echo = defineModule({ name: "echo-binding", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => answered(input, { binding: input.binding ?? "none" }),
			})),
			m.contribute(senderBindings).by(() => ({
				member: "test",
				tokenType: "Test",
				read: async (request) =>
					request.form.has("bind") ? { kind: "bound", confirmation: "k1" } : { kind: "absent" },
			})),
		]);
		const post = await serve([echo], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", bind: "1" }, "echo")).body.binding).toEqual({
			member: "test",
			confirmation: "k1",
			tokenType: "Test",
		});
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body.binding).toBe("none");
	});
});
