import { defineModule, type Module } from "@mod/kernel";
import { httpServers, marks, policies, routes } from "./contract.ts";
import { type Fallback, nodeHttpServer } from "./factory.ts";

/**
 * A test's module contributing the one server to http's `httpServers`, built by `nodeHttpServer` with the
 * fallback given, as an adapter of the http axis does: it refuses boot with what that gives in its place.
 */
export function testServer(fallback?: Fallback): Module {
	return defineModule(
		{ name: "test-server", replicaSafe: true, takes: [marks, policies, routes] },
		(m) => [
			m.contribute(httpServers).by(async (c) => {
				const built = nodeHttpServer({
					routes: await c.collect(routes),
					rules: await c.collect(policies),
					marks: await c.collect(marks),
					...(fallback && { fallback }),
				});
				return built.kind === "refused" ? c.refuseAll(built.refusals) : built.server;
			}),
		],
	);
}
