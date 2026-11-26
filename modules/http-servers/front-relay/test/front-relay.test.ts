import { refusals, wireErrors } from "@mod/front-core-wire";
import { listening, routes } from "@mod/http";
import http from "@mod/http/module";
import httpOps from "@mod/http-ops/module";
import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import frontRelay from "../src/module.ts";
import { frontRelayConfig, type WireCertificates, wireCertificates } from "../src/testing.ts";
import { type Answer, fakeCore } from "./fake-core.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());

const stops: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

const ok = (json: unknown, dpopNonce = ""): ReturnType<Answer> => ({
	outcome: "ok",
	message: { body: new TextEncoder().encode(JSON.stringify(json)), dpopNonce },
});
const refusing = (
	word: (typeof refusals)[number],
	detail = "",
	retryAfter = "",
): ReturnType<Answer> => ({
	outcome: "refused",
	message: { error: refusals.indexOf(word) + 1, detail, dpopNonce: "", retryAfter },
});

const local: Module = defineModule({ name: "local", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/local",
		changesState: false,
		handle: () => ({ status: 200, body: { json: { here: "front" } } }),
	})),
]);

function boot(
	settings: Record<string, unknown>,
	more: readonly Module[] = [],
	log = quietRuntime(),
	httpSettings: Record<string, unknown> = {},
) {
	return assemble({
		modules: [http, tlsOptionsForTests, frontRelay, ...more],
		config: {
			...kernelConfig(),
			http: { port: 0, "cors-origins": ["https://screen.example"], ...httpSettings },
			...frontRelayConfig(certificates, settings),
		},
		runtime: log,
	});
}

/** A Front relaying to a fake Core answering as told; its base URL and the Core. */
async function front(
	answer: Answer,
	settings: Record<string, unknown> = {},
	more: readonly Module[] = [],
) {
	const core = await fakeCore(certificates, answer);
	stops.push(core.close);
	const app = await boot({ "core-port": core.port, ...settings }, more);
	await app.start();
	stops.push(() => app.stop(1000));
	return { url: `http://127.0.0.1:${app.get(listening).port()}`, core, app };
}

const tokenForm = {
	grant_type: "authorization_code",
	code: "abc",
	redirect_uri: "https://rp.example/cb",
	code_verifier: "v".repeat(43),
	client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	client_assertion: "a.b.c",
};
const post = (url: string, form: Record<string, string>, headers: Record<string, string> = {}) =>
	fetch(url, { method: "POST", body: new URLSearchParams(form), headers });

describe("front-relay", () => {
	it("relays an operation the protocol names as its frame, and answers the Core's reply as HTTP", async () => {
		const { url, core } = await front(() => ok({ access_token: "t" }, "n0nce"));
		const answer = await post(`${url}/oauth/token`, tokenForm, { dpop: "d.e.f" });
		expect(answer.status).toBe(200);
		expect(await answer.json()).toEqual({ access_token: "t" });
		expect(answer.headers.get("dpop-nonce")).toBe("n0nce");
		expect(answer.headers.get("cache-control")).toBe("no-store");
		expect(core.seen.map((r) => [r.kind, r.message])).toEqual([
			[
				"token",
				expect.objectContaining({
					grantType: 1,
					code: "abc",
					clientAssertionType: 1,
					dpop: "d.e.f",
				}),
			],
		]);
		expect(core.peers).toEqual(["URI:spiffe://auth.test/front/1"]);
		const refresh = await post(`${url}/oauth/token`, {
			grant_type: "refresh_token",
			refresh_token: "r",
			client_assertion: "a.b.c",
		});
		expect(refresh.status).toBe(200);
		expect(core.seen.at(-1)?.kind).toBe("refresh");
	});

	it("relays a client's own token request (client_credentials) as its operation's frame, its scope and resource carried", async () => {
		const { url, core } = await front(() => ok({ access_token: "t" }));
		const answer = await post(
			`${url}/oauth/token`,
			{
				grant_type: "client_credentials",
				scope: "read",
				resource: "https://api.example",
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: "a.b.c",
			},
			{ dpop: "d.e.f" },
		);
		expect(answer.status).toBe(200);
		expect(core.seen.map((r) => [r.kind, r.message])).toEqual([
			[
				"clientCredentials",
				expect.objectContaining({
					scope: "read",
					resource: "https://api.example",
					clientAssertionType: 1,
					clientAssertion: "a.b.c",
					authorizationDetails: 0,
					dpop: "d.e.f",
				}),
			],
		]);
		// Two resources are more than the frame carries: refused at the Front, nothing sent.
		const two = new URLSearchParams([
			["grant_type", "client_credentials"],
			["resource", "https://a.example"],
			["resource", "https://b.example"],
			["client_assertion", "a.b.c"],
		]);
		const refused = await fetch(`${url}/oauth/token`, { method: "POST", body: two });
		expect(refused.status).toBe(400);
		expect(await refused.json()).toEqual({
			error: "invalid_request",
			error_description: "resource: fieldSyntax",
		});
		expect(core.seen).toHaveLength(1);
	});

	it("answers a refusal with its word's status, and a frame the Core rejected 502", async () => {
		const replies: ReturnType<Answer>[] = [
			refusing("invalid_client"),
			refusing("invalid_grant", "code used"),
			{ outcome: "rejected", message: { code: wireErrors.fieldSyntax } },
		];
		const recorded = recordingLog();
		const core = await fakeCore(certificates, () => replies.shift());
		stops.push(core.close);
		const app = await boot({ "core-port": core.port }, [], quietRuntime({ log: recorded.log }));
		await app.start();
		stops.push(() => app.stop(1000));
		const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
		const first = await post(url, tokenForm);
		expect([first.status, await first.json()]).toEqual([401, { error: "invalid_client" }]);
		const second = await post(url, tokenForm);
		expect([second.status, await second.json()]).toEqual([
			400,
			{ error: "invalid_grant", error_description: "code used" },
		]);
		const third = await post(url, tokenForm);
		expect([third.status, await third.json()]).toEqual([502, { error: "server_error" }]);
		expect(recorded.lines().filter((l) => l.event === "front-relay.rejected")).toMatchObject([
			{ level: "error", fields: { code: "fieldSyntax" } },
		]);
	});

	it("answers a route of the Front's own there, and a request neither takes a fixed 404, relaying neither", async () => {
		const { url, core } = await front(() => ok({}), {}, [local]);
		const own = await fetch(`${url}/local`);
		expect([own.status, await own.json()]).toEqual([200, { here: "front" }]);
		for (const [method, path] of [
			["GET", "/oauth/token"],
			["POST", "/nowhere"],
			["POST", "/local"],
		] as const) {
			const answer = await fetch(`${url}${path}`, { method });
			expect(answer.status, `${method} ${path}`).toBe(404);
		}
		expect(core.seen).toEqual([]);
	});

	it("refuses, sending nothing, a field outside its spec, a name sent twice and a body of another type", async () => {
		const { url, core } = await front(() => ok({}));
		const short = await post(`${url}/oauth/token`, { ...tokenForm, code_verifier: "short" });
		expect([short.status, await short.json()]).toEqual([
			400,
			{ error: "invalid_request", error_description: "codeVerifier: fieldLength" },
		]);
		const twice = await fetch(`${url}/oauth/token`, {
			method: "POST",
			body: `${new URLSearchParams(tokenForm)}&code=again`,
			headers: { "content-type": "application/x-www-form-urlencoded" },
		});
		expect(twice.status).toBe(400);
		const json = await fetch(`${url}/oauth/token`, {
			method: "POST",
			body: JSON.stringify(tokenForm),
			headers: { "content-type": "application/json" },
		});
		expect(json.status).toBe(415);
		const form = await post(`${url}/login/finish`, { statement: "a.b.c", assertion: "x" });
		expect(form.status).toBe(415);
		const mistyped = await fetch(`${url}/login/finish`, {
			method: "POST",
			body: JSON.stringify({ statement: "a.b.c", assertion: 1 }),
			headers: { "content-type": "application/json" },
		});
		expect(mistyped.status).toBe(400);
		expect(core.seen).toEqual([]);
	});

	it("lets the listed origin call the login screen's operations across origins, and no one the token endpoint", async () => {
		const { url } = await front(() => ok({ done: true }));
		const preflight = (path: string) =>
			fetch(`${url}${path}`, {
				method: "OPTIONS",
				headers: {
					origin: "https://screen.example",
					"access-control-request-method": "POST",
					"access-control-request-headers": "content-type",
				},
			});
		const screen = await preflight("/login/finish");
		expect(screen.headers.get("access-control-allow-origin")).toBe("https://screen.example");
		expect(screen.headers.get("access-control-allow-headers")).toBe("content-type");
		expect((await preflight("/oauth/token")).headers.get("access-control-allow-origin")).toBeNull();
		const call = await fetch(`${url}/login/finish`, {
			method: "POST",
			body: JSON.stringify({ statement: "a.b.c", assertion: "x" }),
			headers: { "content-type": "application/json", origin: "https://screen.example" },
		});
		expect([call.status, call.headers.get("access-control-allow-origin")]).toEqual([
			200,
			"https://screen.example",
		]);
	});

	it("answers 503 while the Core is not reached or does not reply in time, and its probe tells so", async () => {
		const silent = await fakeCore(certificates, () => undefined);
		stops.push(silent.close);
		const app = await boot({ "core-port": silent.port, timeout: "200ms" }, [httpOps]);
		await app.start();
		stops.push(() => app.stop(1000));
		const base = `http://127.0.0.1:${app.get(listening).port()}`;
		expect((await post(`${base}/oauth/token`, tokenForm)).status).toBe(503);
		expect((await fetch(`${base}/readyz`)).status).toBe(200);
		await silent.close();
		expect((await post(`${base}/oauth/token`, tokenForm)).status).toBe(503);
		await new Promise((resolve) => setTimeout(resolve, 1100));
		expect((await fetch(`${base}/readyz`)).status).toBe(503);
		expect(silent.seen.map((r) => r.kind)).toEqual(["token"]);
	});

	it("reaches no Core whose certificate its authority did not issue", async () => {
		const core = await fakeCore(certificates, () => ok({}), certificates.stranger);
		stops.push(core.close);
		const app = await boot({ "core-port": core.port, timeout: "500ms" });
		await app.start();
		stops.push(() => app.stop(1000));
		const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
		expect((await post(url, tokenForm)).status).toBe(503);
		expect(core.seen).toEqual([]);
	});

	it("answers at a route of the Front's own that takes a relayed path, exactly or by a wildcard, warning of it at boot", async () => {
		const taking = defineModule({ name: "taking", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(routes).by(() => ({
				method: "POST",
				path: "/oauth/token",
				crossSite: "test",
				unlimited: "test",
				handle: () => ({ status: 200, body: { json: { here: "front" } } }),
			})),
			m.contribute(routes).by(() => ({
				method: "POST",
				path: "/first-key/*",
				crossSite: "test",
				unlimited: "test",
				handle: () => ({ status: 200, body: { json: { here: "front, under" } } }),
			})),
		]);
		const recorded = recordingLog();
		const core = await fakeCore(certificates, () => ok({ here: "core" }));
		stops.push(core.close);
		const app = await boot(
			{ "core-port": core.port },
			[taking],
			quietRuntime({ log: recorded.log }),
		);
		await app.start();
		stops.push(() => app.stop(1000));
		const url = `http://127.0.0.1:${app.get(listening).port()}`;
		expect(await (await post(`${url}/oauth/token`, tokenForm)).json()).toEqual({ here: "front" });
		const under = await fetch(`${url}/first-key/start`, {
			method: "POST",
			body: "{}",
			headers: { "content-type": "application/json" },
		});
		expect(await under.json()).toEqual({ here: "front, under" });
		expect(await (await post(`${url}/login/finish`, {})).status).toBe(415);
		expect(core.seen).toEqual([]);
		expect(
			recorded
				.lines()
				.filter((l) => l.event === "front-relay.shadowed")
				.map((l) => l.fields),
		).toEqual([{ route: "POST /oauth/token" }, { route: "POST /first-key/*" }]);
	});

	it("sends the source the Front determined, and none where its trusted proxy said not who sent it", async () => {
		const { url, core } = await front(() => ok({}));
		await post(
			`${url}/oauth/token`,
			{ ...tokenForm, source: "203.0.113.9" },
			{ source: "203.0.113.9" },
		);
		expect(core.seen.at(-1)?.message.source).toBe("127.0.0.1");
		const behind = await fakeCore(certificates, () => ok({}));
		stops.push(behind.close);
		const app = await boot({ "core-port": behind.port }, [], quietRuntime(), {
			"trusted-proxies": ["127.0.0.1"],
		});
		await app.start();
		stops.push(() => app.stop(1000));
		await post(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, tokenForm);
		expect(behind.seen.at(-1)?.message.source).toBe("");
	});

	it("answers a limit's refusal 429 with when to ask again", async () => {
		const { url } = await front(() => refusing("rate_limited", "", "7"));
		const limited = await post(`${url}/oauth/token`, tokenForm);
		expect([limited.status, limited.headers.get("retry-after"), await limited.json()]).toEqual([
			429,
			"7",
			{ error: "rate_limited" },
		]);
	});

	it("refuses boot where a file cannot be read", async () => {
		const missing = await boot({ "core-port": 1, "key-file": "/nonexistent/key.pem" }).catch(
			(e: unknown) => e,
		);
		expect(BootRefused.is(missing) && missing.refusals).toEqual([
			{ where: "front-relay.key-file", reason: "not readable: write the path of a PEM file" },
		]);
	});
});
