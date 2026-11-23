import frontRelay from "@mod/front-relay/module";
import {
	frontRelayConfig,
	type WireCertificates,
	wireCertificates,
} from "@mod/front-relay/testing";
import { type HttpRequest, jsonAnswer, listening, routes } from "@mod/http";
import http from "@mod/http/module";
import httpOps from "@mod/http-ops/module";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
import { core } from "./boot.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());

const seen: HttpRequest[] = [];
const coreRoutes = defineModule({ name: "core-routes", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "POST",
		path: "/login/finish",
		takes: ["json"],
		crossSite: "the login screen is another site",
		unlimited: "test",
		handle: (request) => {
			seen.push(request);
			return jsonAnswer(200, { done: true });
		},
	})),
	m.contribute(routes).by(() => ({
		method: "POST",
		path: "/token",
		crossSite: "a client's server calls it",
		unlimited: "test",
		handle: () => jsonAnswer(400, { error: "invalid_grant" }),
	})),
]);

it("carries a request at the Front to the Core's route and its answer back, the Front answering its own probe", async () => {
	const coreApp = await core(certificates, [coreRoutes, httpOps]);
	const front = await assemble({
		modules: [http, tlsOptionsForTests, frontRelay, httpOps],
		config: {
			...kernelConfig(),
			http: { port: 0, "cors-origins": ["https://screen.example"] },
			...frontRelayConfig(certificates, { "core-port": coreApp.port }),
		},
		runtime: quietRuntime(),
	});
	await front.start();
	const url = `http://127.0.0.1:${front.get(listening).port()}`;
	let coreStopped = false;
	try {
		const login = await fetch(`${url}/login/finish`, {
			method: "POST",
			body: JSON.stringify({ statement: "a.b.c", assertion: '{"x":1}', extra: "dropped" }),
			headers: { "content-type": "application/json", origin: "https://screen.example" },
		});
		expect([login.status, await login.json()]).toEqual([200, { done: true }]);
		expect(login.headers.get("access-control-allow-origin")).toBe("https://screen.example");
		expect(seen.map((r) => r.json)).toEqual([{ statement: "a.b.c", assertion: '{"x":1}' }]);
		const exchange = await fetch(`${url}/token`, {
			method: "POST",
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: "r",
				client_assertion: "a.b.c",
			}),
		});
		expect([exchange.status, await exchange.json()]).toEqual([400, { error: "invalid_grant" }]);
		expect((await fetch(`${url}/readyz`)).status).toBe(200);
		coreStopped = true;
		await coreApp.stop();
		await new Promise((resolve) => setTimeout(resolve, 1100));
		expect((await fetch(`${url}/readyz`)).status).toBe(503);
	} finally {
		await front.stop(1000);
		if (!coreStopped) await coreApp.stop();
	}
});
