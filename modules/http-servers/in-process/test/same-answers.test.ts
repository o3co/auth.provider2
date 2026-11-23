import coreWire from "@mod/core-wire/module";
import { coreWireConfig } from "@mod/core-wire/testing";
import frontRelay from "@mod/front-relay/module";
import {
	frontRelayConfig,
	type WireCertificates,
	wireCertificates,
} from "@mod/front-relay/testing";
import { applying, jsonAnswer, listening, policies, policy, routes, use } from "@mod/http";
import http from "@mod/http/module";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
import inProcess from "../src/module.ts";

let certificates: WireCertificates;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());

const limit = policy("test.limit");
/** A route behind a policy answering as rate-limit does over its limit. */
const limited = defineModule({ name: "limited", replicaSafe: true, takes: [] }, (m) => [
	m
		.contribute(policies)
		.by(() =>
			applying(limit, () =>
				jsonAnswer(429, { error: "rate_limited" }, { headers: { "retry-after": "7" } }),
			),
		),
	m.contribute(routes).by(() => ({
		method: "POST",
		path: "/token",
		crossSite: "a client's server calls it",
		unlimited: "test",
		uses: [use(limit)],
		handle: () => jsonAnswer(200, {}),
	})),
]);

const started = async (modules: readonly Module[], config: Record<string, unknown>) => {
	const app = await assemble({
		modules: [http, ...modules],
		config: { ...kernelConfig(), ...config },
		runtime: quietRuntime(),
	});
	await app.start();
	return app;
};

const answerOf = async (port: number) => {
	const answer = await fetch(`http://127.0.0.1:${port}/token`, {
		method: "POST",
		body: new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: "r",
			client_assertion: "a.b.c",
		}),
	});
	return [answer.status, answer.headers.get("retry-after"), await answer.json()];
};

it("answers a limit in one process as the Front answers it from the Core", async () => {
	const core = await started([tlsOptionsForTests, coreWire, limited], {
		http: { port: 0, "trusted-proxies": ["127.0.0.1"] },
		...coreWireConfig(certificates),
	});
	const front = await started([tlsOptionsForTests, frontRelay], {
		http: { port: 0 },
		...frontRelayConfig(certificates, { "core-port": core.get(listening).port() }),
	});
	const single = await started([inProcess, limited], { http: { port: 0 } });
	try {
		const relayed = await answerOf(front.get(listening).port());
		expect(relayed).toEqual([429, "7", { error: "rate_limited" }]);
		expect(await answerOf(single.get(listening).port())).toEqual(relayed);
	} finally {
		await front.stop(1000);
		await single.stop(1000);
		await core.stop(1000);
	}
});
