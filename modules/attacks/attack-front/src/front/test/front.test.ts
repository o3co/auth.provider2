import coreWire from "@mod/core-wire/module";
import { coreWireConfig, wireClient } from "@mod/core-wire/testing";
import { carriedOf, type Message } from "@mod/front-core-codec";
import { overHttp, refusals } from "@mod/front-core-wire";
import { type WireCertificates, wireCertificates } from "@mod/front-relay/testing";
import { type HttpRequest, jsonAnswer, listening, routes } from "@mod/http";
import http from "@mod/http/module";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { badFront, type Sent } from "../front.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());
const stops: (() => unknown)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

const token: Message<"token"> = {
	source: "",
	grantType: 1,
	code: "abc",
	redirectUri: "https://rp.example/cb",
	codeVerifier: "v".repeat(43),
	clientAssertionType: 1,
	clientAssertion: "a.b.c",
	clientId: "",
	authorizationDetails: 0,
	dpop: "d.e.f",
};

/** The request a client sends for a message, as HTTP. */
function sentOf(message: Message<"token">): Sent {
	const carried = carriedOf("token", message);
	return {
		path: overHttp.operations.token.path,
		body: Object.fromEntries([...carried.values].map(([name, values]) => [name, values[0] ?? ""])),
		headers: Object.fromEntries(carried.headers),
	};
}

/** A Core of core-wire and a token route answering by `answer`, keeping each request it read. */
async function core(answer: (request: HttpRequest) => ReturnType<typeof jsonAnswer>) {
	const seen: HttpRequest[] = [];
	const route = defineModule({ name: "token-route", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(routes).by(() => ({
			method: "POST",
			path: "/oauth/token",
			crossSite: "a client's server calls it",
			unlimited: "test",
			handle: (request) => {
				seen.push(request);
				return answer(request);
			},
		})),
	]);
	const app = await assemble({
		modules: [http, tlsOptionsForTests, coreWire, route],
		config: {
			...kernelConfig(),
			http: { port: 0, "trusted-proxies": ["127.0.0.1"] },
			...coreWireConfig(certificates),
		},
		runtime: quietRuntime(),
	});
	await app.start();
	stops.push(() => app.stop(1000));
	const wire = await wireClient(app.get(listening).port(), certificates);
	stops.push(wire.close);
	return { wire, seen };
}

describe("the dishonest Front", () => {
	it("relays a request as its operation, declaring its own source, and answers the Core's reply as HTTP", async () => {
		const { wire, seen } = await core(() =>
			jsonAnswer(200, { access_token: "t" }, { headers: { "dpop-nonce": "n0" } }),
		);
		const front = badFront(wire, "203.0.113.9");
		const answered = await front.post(sentOf(token));
		expect(answered).toEqual({ status: 200, body: { access_token: "t" }, dpopNonce: "n0" });
		expect(seen[0]?.source).toMatchObject({ address: "203.0.113.9", determined: true });
		expect(front.seen()).toEqual([
			expect.objectContaining({ kind: "token", message: { ...token, source: "203.0.113.9" } }),
		]);
	});

	it("changes the message a step's rewrite names, and the reply, and nothing else", async () => {
		const { wire, seen } = await core((request) =>
			jsonAnswer(200, { code: request.fields.single("code") }),
		);
		const front = badFront(wire, "203.0.113.9");
		front.rewrite({ messages: { token: (message) => ({ ...message, code: "xyz" }) } });
		const answered = await front.post(sentOf(token));
		expect(seen).toHaveLength(1);
		expect(answered).toMatchObject({ status: 200, body: { code: "xyz" } });
		front.rewrite({
			replies: {
				token: (reply) => ({
					outcome: "refused",
					id: reply.id,
					message: {
						error: refusals.indexOf("invalid_grant") + 1,
						detail: "x",
						dpopNonce: "",
						retryAfter: "",
					},
				}),
			},
		});
		expect(await front.post(sentOf(token))).toEqual({
			status: 400,
			body: { error: "invalid_grant", error_description: "x" },
		});
	});

	it("answers a refusal with its word's status, and a request of no operation or field it cannot carry as an honest Front does", async () => {
		const { wire } = await core(() => jsonAnswer(400, { error: "invalid_client" }));
		const front = badFront(wire, "203.0.113.9");
		expect(await front.post(sentOf(token))).toMatchObject({
			status: 401,
			body: { error: "invalid_client" },
		});
		expect(await front.post({ path: "/nowhere", body: {} })).toEqual({
			status: 404,
			body: undefined,
		});
		const loose = sentOf(token);
		expect(await front.post({ ...loose, body: { ...loose.body, code: "!" } })).toEqual({
			status: 400,
			body: { error: "invalid_request" },
		});
	});

	it("answers a limit's Retry-After, and a refusal of no detail without a description, as front-relay does", async () => {
		const { wire } = await core(() =>
			jsonAnswer(429, { error: "rate_limited" }, { headers: { "retry-after": "7" } }),
		);
		const front = badFront(wire, "203.0.113.9");
		expect(await front.post(sentOf(token))).toEqual({
			status: 429,
			body: { error: "rate_limited" },
			retryAfter: "7",
		});
	});

	it("sends frames of its own beside what it relays", async () => {
		const { wire, seen } = await core(() => jsonAnswer(200, {}));
		const front = badFront(wire, "203.0.113.9");
		const reply = await front.send("token", { ...token, source: "198.51.100.1" });
		expect(reply.outcome).toBe("ok");
		expect(seen[0]?.source).toMatchObject({ address: "198.51.100.1", determined: true });
	});
});
