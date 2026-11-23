import {
	applying,
	httpServers,
	listening,
	policy,
	type Route,
	type ServerInput,
	use,
} from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, type BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { proxiesOf } from "@mod/request-source";
import { expect, it } from "vitest";
import { nodeHttpServer } from "../src/factory.ts";
import { testServer } from "../src/testing.ts";

const config = { ...kernelConfig(), ...httpConfig() };
const runtime = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

it("is the one server http's httpServers takes, contributed by the module that builds it", async () => {
	const counted = contract<number>("test.servers");
	const counting = defineModule(
		{ name: "counting", replicaSafe: false, takes: [httpServers] },
		(m) => [m.provide(counted).by(async (c) => (await c.collect(httpServers)).length)],
	);
	const app = await assemble({ modules: [http, testServer(), counting], config, runtime });
	expect(app.get(counted)).toBe(1);
});

it("contributes no server itself: http alone is refused for want of one", async () => {
	const refused = await assemble({ modules: [http], config, runtime }).catch(
		(error: BootRefused) => error.refusals,
	);
	expect(refused).toEqual([
		{
			where: "http.servers",
			reason: "needs exactly one contribution (0): compose one adapter of the http axis",
		},
	]);
});

it("leaves a module building it taking every handle its takes name", async () => {
	expect(
		(await takesUnused({ modules: [http, testServer()], config }))["test-server"],
	).toBeUndefined();
});

it("opens no listener in an assembly that is never started", async () => {
	const app = await assemble({
		modules: [http, testServer()],
		config,
		runtime: quietRuntime(),
		neverStarted: true,
	});
	await expect(app.start()).rejects.toThrow(TypeError);
	expect(() => app.get(listening).port()).toThrow("http is not listening yet");
	await app.stop(1000);
});

it("gives the boot's refusals in place of a server, guarding the routes once", async () => {
	const unruled = policy("test.unruled");
	const route: Route = {
		method: "GET",
		path: "/gated",
		changesState: false,
		uses: [use(unruled)],
		handle: () => ({ status: 204 }),
	};
	expect(nodeHttpServer({ routes: [route], rules: [], marks: [] })).toEqual({
		kind: "refused",
		refusals: [
			{ where: "http.routes:GET /gated", reason: "uses a policy no module applies: test.unruled" },
		],
	});
	const built = nodeHttpServer({
		routes: [route],
		rules: [applying(unruled, () => "pass")],
		marks: [],
	});
	expect(built.kind).toBe("server");
});

it("refuses to start on routes other than those it guarded at boot", async () => {
	const built = nodeHttpServer({ routes: [], rules: [], marks: [] });
	if (built.kind !== "server") throw new Error("built no server");
	const input: ServerInput = {
		routes: [
			{ method: "GET", path: "/late", changesState: false, handle: () => ({ status: 204 }) },
		],
		settings: {
			host: "127.0.0.1",
			port: 0,
			proxies: proxiesOf({ "trusted-proxies": [], "proxy-hops": 1 }),
			origins: new Set(),
			limits: { headersMs: 1000, requestMs: 1000, connections: 10 },
		},
		ends: [],
		log: recordingLog().log,
		clock: { now: () => 0 },
	};
	await expect(built.server.serve(input)).rejects.toThrow(
		"serves only the routes nodeHttpServer guarded at boot, and was handed others",
	);
});
