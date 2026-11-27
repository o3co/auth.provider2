import { createServer } from "node:net";
import { encodeRequest } from "@mod/front-core-codec";
import { refusals, wireErrors } from "@mod/front-core-wire";
import { type WireCertificates, wireCertificates } from "@mod/front-relay/testing";
import {
	applying,
	type HttpRequest,
	type HttpResponse,
	jsonAnswer,
	policies,
	policy,
	type RequestEnd,
	type Route,
	requestEnds,
	routes,
	use,
} from "@mod/http";
import httpOps from "@mod/http-ops/module";
import { BootRefused, defineModule, type Module } from "@mod/kernel";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { wireClient } from "../src/testing.ts";
import { core, tokenMessage } from "./boot.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());
const stops: (() => unknown)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

const word = (w: (typeof refusals)[number]) => refusals.indexOf(w) + 1;
const seen: HttpRequest[] = [];
const ended: RequestEnd[] = [];
afterEach(() => {
	seen.length = 0;
	ended.length = 0;
});

/** The Core's token route, answering as told, and an observer of each request's end. */
function token(answer: (request: HttpRequest) => HttpResponse, more: Partial<Route> = {}): Module {
	return defineModule({ name: "token-route", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(routes).by(() => ({
			method: "POST",
			path: "/oauth/token",
			crossSite: "a client's server calls it",
			unlimited: "test",
			handle: (request) => {
				seen.push(request);
				return answer(request);
			},
			...more,
		})),
		m.contribute(requestEnds).by(() => ({ ended: (end) => ended.push(end) })),
	]);
}

async function started(modules: readonly Module[], settings: Record<string, unknown> = {}) {
	const app = await core(certificates, modules, settings);
	stops.push(app.stop);
	return app;
}

async function client(port: number, shows = certificates.front) {
	const made = await wireClient(port, certificates, shows);
	stops.push(made.close);
	return made;
}

describe("core-wire", () => {
	it("hands a frame to the route its operation names, rebuilt as the route reads a request, and replies with the answer", async () => {
		const app = await started([
			token(() => jsonAnswer(200, { access_token: "t" }, { headers: { "dpop-nonce": "n0" } })),
		]);
		const front = await client(app.port);
		const reply = await front.send("token", 7, tokenMessage());
		expect(reply).toEqual({
			outcome: "ok",
			id: 7,
			message: { body: new TextEncoder().encode('{"access_token":"t"}'), dpopNonce: "n0" },
		});
		const [request] = seen;
		expect(request?.fields.single("grant_type")).toBe("authorization_code");
		expect(request?.fields.single("code_verifier")).toBe("v".repeat(43));
		expect(request?.fields.has("client_id")).toBe(false);
		expect(request?.headers.get("dpop")).toBe("d.e.f");
		expect(request?.source).toMatchObject({
			address: "203.0.113.5",
			scheme: "https",
			determined: true,
		});
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(ended).toEqual([
			expect.objectContaining({ method: "POST", route: "/oauth/token", status: 200 }),
		]);
	});

	it("hands a client's own token request to the token route, rebuilt as the client's form with its grant type", async () => {
		const app = await started([token(() => jsonAnswer(200, { access_token: "t" }))]);
		const front = await client(app.port);
		const reply = await front.send("clientCredentials", 3, {
			source: "203.0.113.7",
			scope: "read write",
			resource: "https://api.example",
			clientAssertionType: 1,
			clientAssertion: "a.b.c",
			clientId: "svc",
			authorizationDetails: 0,
			dpop: "d.e.f",
		});
		expect(reply.outcome).toBe("ok");
		const [request] = seen;
		expect(request?.fields.single("grant_type")).toBe("client_credentials");
		expect(request?.fields.single("scope")).toBe("read write");
		expect(request?.fields.single("resource")).toBe("https://api.example");
		expect(request?.fields.single("client_assertion")).toBe("a.b.c");
		expect(request?.fields.single("client_id")).toBe("svc");
		expect(request?.fields.has("authorization_details")).toBe(false);
		expect(request?.headers.get("dpop")).toBe("d.e.f");
		expect(request?.source).toMatchObject({ address: "203.0.113.7", determined: true });
	});

	it("relays a DPoP nonce as long and of the characters as the wire's field takes, and none outside them", async () => {
		// dpop's form: the time bucket's digits, then its MAC in base64url, 59 characters.
		const long = `${"1".repeat(16)}${"A".repeat(42)}Q`;
		const sent: string[] = [long, `${"1".repeat(16)}.${"A".repeat(42)}Q`, "n".repeat(65)];
		const app = await started([
			token(() => jsonAnswer(200, {}, { headers: { "dpop-nonce": sent.shift() ?? "" } })),
		]);
		const front = await client(app.port);
		const nonces: string[] = [];
		for (let id = 1; id <= 3; id++) {
			const reply = await front.send("token", id, tokenMessage(`c${id}`));
			nonces.push(reply.outcome === "ok" ? reply.message.dpopNonce : "not ok");
		}
		expect(long).toHaveLength(59);
		expect(nonces).toEqual([long, "", ""]);
	});

	it("replies a refusal the wire names with its word and detail, 503 as temporarily_unavailable, anything else server_error", async () => {
		const answers: HttpResponse[] = [
			jsonAnswer(400, { error: "invalid_grant", error_description: "used\nonce" }),
			jsonAnswer(503, { error: "service_unavailable" }),
			{ status: 201 },
			jsonAnswer(400, { error: "made_up" }),
			// RFC 8707's word, the token endpoint's answer to a resource it issues for no audience.
			jsonAnswer(400, { error: "invalid_target", error_description: "one resource at most" }),
			// The token endpoint's word for a grant its client may not use (RFC 6749 §5.2), relayed as it is.
			jsonAnswer(400, { error: "unauthorized_client", error_description: "not this grant" }),
		];
		const app = await started([token(() => answers.shift() ?? { status: 500 })]);
		const front = await client(app.port);
		const messages = [];
		for (const id of [1, 2, 3, 4, 5, 6])
			messages.push((await front.send("token", id, tokenMessage())).message);
		expect(messages).toEqual([
			{ error: word("invalid_grant"), detail: "used once", dpopNonce: "", retryAfter: "" },
			{ error: word("temporarily_unavailable"), detail: "", dpopNonce: "", retryAfter: "" },
			{ error: word("server_error"), detail: "", dpopNonce: "", retryAfter: "" },
			{ error: word("server_error"), detail: "", dpopNonce: "", retryAfter: "" },
			{
				error: word("invalid_target"),
				detail: "one resource at most",
				dpopNonce: "",
				retryAfter: "",
			},
			{
				error: word("unauthorized_client"),
				detail: "not this grant",
				dpopNonce: "",
				retryAfter: "",
			},
		]);
		expect(app.lines().filter((l) => l.event === "core-wire.unrelayable")).toHaveLength(2);
	});

	it("replies server_error for an answer whose written JSON holds a null, as http's servers refuse one, naming the paths and never the values, the end told 500 [oidc-core-13.3-a]", async () => {
		const answers: HttpResponse[] = [
			jsonAnswer(200, { access_token: "secret-value", scope: null, list: [1, null] }),
			// What JSON writes as null is one: a number that is none, undefined in a list.
			jsonAnswer(200, { expires_in: Math.ceil(Number.NaN), list: [undefined] }),
			jsonAnswer(200, { access_token: "t" }),
			// A refusal is rebuilt from its strings, so a null beside its error is not relayed.
			jsonAnswer(400, { error: "invalid_grant", x: null }),
			// A value JSON writes as nothing is relayed as it always was: an empty body.
			jsonAnswer(200, { toJSON: () => undefined }),
		];
		const app = await started([token(() => answers.shift() ?? { status: 500 })]);
		const front = await client(app.port);
		const replies = [];
		for (const id of [1, 2, 3, 4, 5]) replies.push(await front.send("token", id, tokenMessage()));
		const refusal = { error: word("server_error"), detail: "", dpopNonce: "", retryAfter: "" };
		expect(replies.map((r) => [r.outcome, r.message])).toEqual([
			["refused", refusal],
			["refused", refusal],
			["ok", { body: new TextEncoder().encode('{"access_token":"t"}'), dpopNonce: "" }],
			["refused", { ...refusal, error: word("invalid_grant") }],
			["ok", { body: new Uint8Array(), dpopNonce: "" }],
		]);
		expect(app.lines().filter((l) => l.level === "error")).toEqual([
			{
				level: "error",
				event: "http.failed",
				fields: { kind: "null_member", route: "/oauth/token", members: "scope list[1]" },
			},
			{
				level: "error",
				event: "http.failed",
				fields: { kind: "null_member", route: "/oauth/token", members: "expires_in list[0]" },
			},
		]);
		expect(JSON.stringify(app.lines())).not.toContain("secret-value");
		expect(app.lines().some((l) => l.event === "core-wire.unrelayable")).toBe(false);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(ended.map((e) => e.status)).toEqual([500, 500, 200, 400, 200]);
	});

	it("replies server_error for an answer JSON cannot write, as http's servers answer one, its end told 500", async () => {
		const app = await started([token(() => jsonAnswer(200, { n: 1n }))]);
		const front = await client(app.port);
		expect((await front.send("token", 1, tokenMessage())).message).toEqual({
			error: word("server_error"),
			detail: "",
			dpopNonce: "",
			retryAfter: "",
		});
		expect(app.lines().filter((l) => l.level === "error")).toEqual([
			{ level: "error", event: "http.unwritable", fields: { kind: "TypeError" } },
		]);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(ended.map((e) => e.status)).toEqual([500]);
	});

	it("holds an answer nested deep, within the reply's size, to the same rule: relayed clean, refused with a null at its bottom", async () => {
		const deep = (leaf: unknown) => {
			let value: unknown = leaf;
			for (let i = 0; i < 4000; i++) value = { a: value };
			return value;
		};
		const answers = [jsonAnswer(200, deep("x")), jsonAnswer(200, deep(null))];
		const app = await started([token(() => answers.shift() ?? { status: 500 })]);
		const front = await client(app.port);
		expect((await front.send("token", 1, tokenMessage())).outcome).toBe("ok");
		expect((await front.send("token", 2, tokenMessage())).message).toMatchObject({
			error: word("server_error"),
		});
		expect(app.lines().filter((l) => l.level === "error")).toEqual([
			expect.objectContaining({
				event: "http.failed",
				fields: expect.objectContaining({ kind: "null_member" }),
			}),
		]);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(ended.map((e) => e.status)).toEqual([200, 500]);
	});

	it("applies the route's policies first, and refuses boot where a route uses a policy no module applies", async () => {
		const gate = policy("test.gate");
		const rule = defineModule({ name: "gate", replicaSafe: true, takes: [] }, (m) => [
			m
				.contribute(policies)
				.by(() => applying(gate, () => jsonAnswer(403, { error: "access_denied" }))),
		]);
		const app = await started([token(() => jsonAnswer(200, {}), { uses: [use(gate)] }), rule]);
		const front = await client(app.port);
		expect((await front.send("token", 1, tokenMessage())).message).toMatchObject({
			error: word("access_denied"),
		});
		expect(seen).toEqual([]);
		const refused = await core(certificates, [
			token(() => jsonAnswer(200, {}), { uses: [use(gate)] }),
		]).catch((e: unknown) => e);
		expect(BootRefused.is(refused) && refused.refusals).toEqual([
			{
				where: "http.routes:POST /oauth/token",
				reason: "uses a policy no module applies: test.gate",
			},
		]);
	});

	it("takes the source the Front declared as its trusted proxies are read, undetermined where none is declared or the Front is not trusted", async () => {
		const app = await started([token(() => jsonAnswer(200, {}))]);
		const front = await client(app.port);
		await front.send("token", 1, tokenMessage("abc", ""));
		expect(seen.at(-1)?.source).toMatchObject({ address: "127.0.0.1", determined: false });
		const untrusting = await core(certificates, [token(() => jsonAnswer(200, {}))], {}, {});
		stops.push(untrusting.stop);
		const other = await client(untrusting.port);
		await other.send("token", 2, tokenMessage());
		expect(seen.at(-1)?.source).toMatchObject({ address: "127.0.0.1", determined: true });
	});

	it("replies a limit's refusal with when to ask again", async () => {
		const app = await started([
			token(() => jsonAnswer(429, { error: "rate_limited" }, { headers: { "retry-after": "7" } })),
		]);
		const front = await client(app.port);
		expect((await front.send("token", 1, tokenMessage())).message).toEqual({
			error: word("rate_limited"),
			detail: "",
			dpopNonce: "",
			retryAfter: "7",
		});
		expect(app.lines().some((l) => l.event === "core-wire.unrelayable")).toBe(false);
	});

	it("refuses boot where an operation's route takes no body of the operation's, and warns of a route no operation reaches", async () => {
		const login = (takes?: readonly ("form" | "json")[]) =>
			defineModule({ name: "login", replicaSafe: true, takes: [] }, (m) => [
				m.contribute(routes).by(() => ({
					method: "POST",
					path: "/login/finish",
					crossSite: "test",
					unlimited: "test",
					...(takes && { takes }),
					handle: () => jsonAnswer(200, {}),
				})),
			]);
		const refused = await core(certificates, [login()]).catch((e: unknown) => e);
		expect(BootRefused.is(refused) && refused.refusals).toEqual([
			{
				where: "http.routes:POST /login/finish",
				reason: "takes no json body, which the wire's loginFinish is",
			},
		]);
		const elsewhere = defineModule({ name: "elsewhere", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(routes).by(() => ({
				method: "GET",
				path: "/elsewhere",
				changesState: false,
				handle: () => ({ status: 200 }),
			})),
		]);
		const app = await started([login(["json"]), elsewhere]);
		expect(
			app
				.lines()
				.filter((l) => l.event === "core-wire.unreached")
				.map((l) => l.fields),
		).toEqual([{ route: "GET /elsewhere" }]);
	});

	it("replies server_error to an operation no route of the Core takes", async () => {
		const app = await started([token(() => jsonAnswer(200, {}))]);
		const front = await client(app.port);
		const reply = await front.send("loginFinish", 3, {
			source: "",
			statement: "a.b.c",
			assertion: "x",
		});
		expect(reply.message).toMatchObject({ error: word("server_error") });
		expect(app.lines().find((l) => l.event === "core-wire.no_route")?.fields).toEqual({
			kind: "loginFinish",
		});
	});

	it("rejects a frame no honest Front sends with its code alone, warns of the instance, and ends the connection", async () => {
		const app = await started([token(() => jsonAnswer(200, {}))]);
		const front = await client(app.port);
		const frame = encodeRequest("token", 5, tokenMessage());
		frame[frame.length - 1] = 0x20; // the DPoP proof's last character, outside its syntax
		expect(await front.raw(frame, 5)).toEqual({
			outcome: "rejected",
			id: 5,
			message: { code: wireErrors.fieldSyntax },
		});
		await front.closed;
		expect(app.lines().find((l) => l.event === "core-wire.violation")).toMatchObject({
			level: "warn",
			fields: { instance: "spiffe://auth.test/front/1", code: "fieldSyntax" },
		});
		expect(seen).toEqual([]);
		// Notified alone: the instance connects again; a second violation within the minute is held, not written.
		const again = await client(app.port);
		expect((await again.send("token", 6, tokenMessage())).outcome).toBe("ok");
		expect((await again.raw(frame, 5)).outcome).toBe("rejected");
		expect(app.lines().filter((l) => l.event === "core-wire.violation")).toHaveLength(1);
	});

	it("cuts an instance that sent a violation, when the operator chose to, and no other", async () => {
		const app = await started([token(() => jsonAnswer(200, {}))], { "on-violation": "cut" });
		const other = await client(app.port, certificates.otherFront);
		const front = await client(app.port);
		const versionless = encodeRequest("token", 1, tokenMessage());
		versionless[0] = 9;
		expect((await front.raw(versionless, 0)).message).toEqual({ code: wireErrors.version });
		expect(app.lines().some((l) => l.event === "core-wire.version_refused")).toBe(true);
		const still = await client(app.port);
		const bad = encodeRequest("token", 2, tokenMessage());
		bad[1] = 0x7f;
		expect((await still.raw(bad, 2)).message).toEqual({ code: wireErrors.kind });
		const cut = await client(app.port);
		await cut.closed;
		expect(app.lines().map((l) => l.event)).toEqual(
			expect.arrayContaining(["core-wire.violation", "core-wire.cut", "core-wire.cut_refused"]),
		);
		expect((await other.send("token", 3, tokenMessage())).outcome).toBe("ok");
		const unnamed = await client(app.port, certificates.unnamedFront);
		await unnamed.closed;
		expect(app.lines().find((l) => l.event === "core-wire.unnamed_refused")?.fields).toEqual({
			instance: "unnamed-front",
		});
	});

	it("leaves no probe listener open where the wire cannot listen", async () => {
		const taken = await started([token(() => jsonAnswer(200, {}))]);
		const probePort = await freePort();
		const failing = await core(
			certificates,
			[token(() => jsonAnswer(200, {})), httpOps],
			{ "probe-port": probePort },
			{ port: taken.port },
		).catch((e: unknown) => e);
		expect(failing).toBeInstanceOf(Error);
		// The probe's port is free again: it listens once more.
		expect(await freePort(probePort)).toBe(probePort);
	});

	it("takes no connection without a certificate its authority issued", async () => {
		const app = await started([token(() => jsonAnswer(200, {}))]);
		for (const shows of [certificates.stranger, "none"] as const) {
			const made = await wireClient(app.port, certificates, shows);
			stops.push(made.close);
			made.socket.write(encodeRequest("token", 1, tokenMessage()));
			await made.closed;
		}
		expect(seen).toEqual([]);
	});

	it("serves the probe routes on the probe listener alone", async () => {
		const app = await started([token(() => jsonAnswer(200, {})), httpOps]);
		const probe = `http://127.0.0.1:${app.probePort}`;
		expect((await fetch(`${probe}/readyz`)).status).toBe(200);
		expect((await fetch(`${probe}/_healthcheck`)).status).toBe(200);
		expect((await fetch(`${probe}/oauth/token`, { method: "POST" })).status).toBe(404);
		const front = await client(app.port);
		expect((await front.send("token", 1, tokenMessage())).outcome).toBe("ok");
	});
});

/** A port free now: `port` where it is, else any. */
function freePort(port = 0): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = createServer();
		server.once("error", reject);
		server.listen(port, "127.0.0.1", () => {
			const { port: took } = server.address() as { port: number };
			server.close(() => resolve(took));
		});
	});
}
