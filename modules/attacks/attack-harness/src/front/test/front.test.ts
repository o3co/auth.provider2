import coreWire from "@mod/core-wire/module";
import { coreWireConfig, wireClient } from "@mod/core-wire/testing";
import { carriedOf, type Message, WireEncodeError } from "@mod/front-core-codec";
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
		expect(answered).toMatchObject({ status: 200, body: { access_token: "t" }, dpopNonce: "n0" });
		expect(answered.wire?.outcome).toBe("ok");
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
		const rewritten = await front.post(sentOf(token));
		expect(rewritten).toMatchObject({
			status: 400,
			body: { error: "invalid_grant", error_description: "x" },
		});
		// The Core's own reply stays as it came: the refusal is the Front's.
		expect(rewritten.wire?.outcome).toBe("ok");
	});

	it("applies a rewrite it works out before the message goes", async () => {
		const { wire, seen } = await core((request) =>
			jsonAnswer(200, { code: request.fields.single("code") }),
		);
		const front = badFront(wire, "203.0.113.9");
		front.rewrite({
			messages: {
				token: async (message) => {
					await new Promise((resolve) => setTimeout(resolve, 1));
					return { ...message, code: "later" };
				},
			},
		});
		expect(await front.post(sentOf(token))).toMatchObject({ status: 200, body: { code: "later" } });
		expect(seen).toHaveLength(1);
	});

	it("answers a rewrite the frame cannot carry as one it cannot send, nothing sent", async () => {
		const { wire, seen } = await core(() => jsonAnswer(200, {}));
		const front = badFront(wire, "203.0.113.9");
		front.rewrite({
			messages: {
				token: () => {
					throw new WireEncodeError("code", "fieldSyntax");
				},
			},
		});
		expect(await front.post(sentOf(token))).toEqual({
			status: 400,
			body: { error: "invalid_request" },
		});
		expect(seen).toHaveLength(0);
		expect(front.seen()).toEqual([]);
	});

	it("sends frames of its own beside what it relays", async () => {
		const { wire, seen } = await core(() => jsonAnswer(200, {}));
		const front = badFront(wire, "203.0.113.9");
		const reply = await front.send("token", { ...token, source: "198.51.100.1" });
		expect(reply.outcome).toBe("ok");
		expect(seen[0]?.source).toMatchObject({ address: "198.51.100.1", determined: true });
		// Kept beside what it relays, in the order sent, with the reply as it came.
		const relayed = await front.post(sentOf(token));
		expect(front.seen().map((r) => [r.kind, r.message.source, r.reply.id])).toEqual([
			["token", "198.51.100.1", 1],
			["token", "203.0.113.9", 2],
		]);
		expect(relayed.wire?.id).toBe(2);
	});
});
