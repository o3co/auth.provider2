import { authorizationRequests, type RequestSource, requestSources } from "@mod/authorize";
import { authorizationRequestsStandIn } from "@mod/authorize/testing";
import { clientAssertion } from "@mod/client-assertion";
import { clients } from "@mod/clients";
import { overHttp } from "@mod/front-core-wire";
import { type Route, routes } from "@mod/http";
import { issuer, type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { senderBinding } from "@mod/sender-binding";
import { expect, it } from "vitest";
import { pushedRequests } from "../src/contract.ts";
import par from "../src/module.ts";
import { parConfig } from "../src/testing.ts";

const seen = contract<{
	readonly routes: readonly Route[];
	readonly metadata: readonly MetadataItem[];
	readonly sources: readonly RequestSource[];
}>("test.seen");

it("serves the wire's par path under a per-source policy, publishes it, and gives authorize the request_uri source", async () => {
	const fakes = defineModule(
		{ name: "fakes", replicaSafe: true, takes: [routes, metadata, requestSources] },
		(m) => [
			m.provide(clients).by(() => ({}) as never),
			m.provide(clientAssertion).by(() => ({}) as never),
			m.provide(senderBinding).by(() => ({}) as never),
			m.provide(pushedRequests).by(() => ({}) as never),
			m.provide(authorizationRequests).by(() => authorizationRequestsStandIn()),
			m
				.provide(issuer)
				.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://front.example" })),
			m.provide(seen).by(async (c) => ({
				routes: await c.collect(routes),
				metadata: await c.collect(metadata),
				sources: await c.collect(requestSources),
			})),
		],
	);
	const booted = async (section: Record<string, unknown> = {}) =>
		(
			await assemble({
				modules: [fakes, par],
				config: { ...kernelConfig(), ...parConfig(section) },
				runtime: quietRuntime(),
			})
		).get(seen);
	const { routes: served, metadata: items, sources } = await booted();
	expect(served.map((r) => `${r.method} ${r.path}`)).toEqual([
		`POST ${overHttp.operations.par.path}`,
	]);
	expect(served[0]?.uses).toHaveLength(1);
	// Pushed alone by default (FAPI 2.0): the source is the only one taken, and the metadata says so.
	expect(items).toEqual([
		{ name: "require_pushed_authorization_requests", value: true },
		{ name: "pushed_authorization_request_endpoint", value: "https://front.example/oauth/par" },
	]);
	expect(sources.map((s) => [s.name, s.only, s.readsRequestUri])).toEqual([
		["request_uri", true, true],
	]);
	// Turned off, a JAR by value is taken too, and the metadata says so.
	const byValueToo = await booted({ "pushed-only": false });
	expect(byValueToo.metadata).toContainEqual({
		name: "require_pushed_authorization_requests",
		value: false,
	});
	expect(byValueToo.sources.map((s) => s.only)).toEqual([false]);
});
