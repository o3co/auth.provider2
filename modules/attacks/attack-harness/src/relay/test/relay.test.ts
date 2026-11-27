import coreWire from "@mod/core-wire/module";
import { coreWireConfig, wireClient } from "@mod/core-wire/testing";
import { carriedOf, type Message, type WireReply } from "@mod/front-core-codec";
import { overHttp } from "@mod/front-core-wire";
import { type WireCertificates, wireCertificates } from "@mod/front-relay/testing";
import { type HttpRequest, jsonAnswer, listening, routes } from "@mod/http";
import http from "@mod/http/module";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { carrier, honestRelay, read, type Sent, type Wire } from "../relay.ts";

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

describe("the honest relay", () => {
	it("relays a request as its operation, declaring its own source, and answers the Core's reply as HTTP", async () => {
		const { wire, seen } = await core(() =>
			jsonAnswer(200, { access_token: "t" }, { headers: { "dpop-nonce": "n0" } }),
		);
		const answered = await honestRelay(wire, "203.0.113.9").post(sentOf(token));
		expect(answered).toMatchObject({ status: 200, body: { access_token: "t" }, dpopNonce: "n0" });
		expect(answered.wire?.outcome).toBe("ok");
		expect(seen[0]?.source).toMatchObject({ address: "203.0.113.9", determined: true });
		expect(seen[0]?.fields.single("code")).toBe("abc");
	});

	it("answers a refusal with its word's status, and a request of no operation or field it cannot carry as front-relay does", async () => {
		const { wire, seen } = await core(() => jsonAnswer(400, { error: "invalid_client" }));
		const front = honestRelay(wire, "203.0.113.9");
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
			body: { error: "invalid_request", error_description: "code: fieldSyntax" },
		});
		// The request object the frame cannot carry is its own word, as front-relay answers it.
		const pushed = (request?: string) => ({
			path: overHttp.operations.par.path,
			body: {
				...(request !== undefined && { request }),
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: "a.b.c",
			},
		});
		expect(await front.post(pushed("a.b."))).toEqual({
			status: 400,
			body: { error: "invalid_request_object", error_description: "request: fieldSyntax" },
		});
		expect(await front.post(pushed())).toEqual({
			status: 400,
			body: { error: "invalid_request", error_description: "request: fieldLength" },
		});
		expect(seen).toHaveLength(1);
	});

	it("answers a limit's Retry-After, and a refusal of no detail without a description, as front-relay does", async () => {
		const { wire } = await core(() =>
			jsonAnswer(429, { error: "rate_limited" }, { headers: { "retry-after": "7" } }),
		);
		expect(await honestRelay(wire, "203.0.113.9").post(sentOf(token))).toMatchObject({
			status: 429,
			body: { error: "rate_limited" },
			retryAfter: "7",
		});
	});
});

describe("the relay's parts", () => {
	it("reads a request as its operation and message, the source given", () => {
		expect(read(sentOf(token), "203.0.113.9")).toEqual({
			kind: "token",
			message: { ...token, source: "203.0.113.9" },
		});
		expect(read({ path: "/nowhere", body: {} }, "203.0.113.9")).toEqual({
			answered: { status: 404, body: undefined },
		});
	});

	it("carries each frame on its wire with the next id, whoever sends it", async () => {
		const ids: number[] = [];
		const wire: Wire = {
			send: async (_kind, id) => {
				ids.push(id);
				return { outcome: "rejected", id } as unknown as WireReply;
			},
		};
		const carry = carrier(wire);
		await carry.send("token", token);
		await carry.send("token", token);
		expect(ids).toEqual([1, 2]);
	});
});
