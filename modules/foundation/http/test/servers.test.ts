import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { listening, policy, type Route, routes, use } from "../src/contract.ts";
import { boot, contributing, double, refusalsOf } from "./boot.ts";

const unapplied = policy("test.unapplied");
const route = defineModule({ name: "handlers", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/a",
		changesState: false,
		handle: () => ({ status: 204 }),
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/b",
		changesState: false,
		uses: [use(unapplied)],
		handle: () => ({ status: 204 }),
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/ready",
		changesState: false,
		exposure: "probe",
		handle: () => ({ status: 204 }),
	})),
]);

describe("the server serving the routes", () => {
	it("is the one contributed: given the declared routes, the settings and the observers at start, drained at stop", async () => {
		const { seen, server } = double(4321);
		const app = await boot(
			{ host: "127.0.0.1", "cors-origins": ["https://app.example"] },
			{ modules: [route], servers: [contributing("server", server)] },
		);
		expect(seen.input).toBeUndefined();
		expect(() => app.get(listening).port()).toThrow();
		await app.start();
		expect(app.get(listening).port()).toBe(4321);
		expect(seen.input?.routes.map((r) => r.path)).toEqual(["/a", "/b", "/ready"]);
		expect(seen.input?.settings).toMatchObject({ host: "127.0.0.1", port: 0 });
		expect([...(seen.input?.settings.origins ?? [])]).toEqual(["https://app.example"]);
		expect(seen.input?.ends).toEqual([]);
		await app.stop(1000);
		expect(seen.drained).toBe(true);
	});

	it("is refused at boot when none or two are contributed", async () => {
		expect(await refusalsOf(boot({}, { servers: [] }))).toEqual([
			["http.servers", "needs exactly one contribution (0): compose one adapter of the http axis"],
		]);
		const two = [contributing("one", double(1).server), contributing("two", double(2).server)];
		expect(await refusalsOf(boot({}, { servers: two }))).toEqual([
			["http.servers", "needs exactly one contribution (2)"],
		]);
	});

	it("hands each route with the listener it says it is served on, the ordinary one unless it says so", async () => {
		const { seen, server } = double();
		const app = await boot({}, { modules: [route], servers: [contributing("server", server)] });
		await app.start();
		expect(seen.input?.routes.map((r) => r.exposure ?? "ordinary")).toEqual([
			"ordinary",
			"ordinary",
			"probe",
		]);
		await app.stop(1000);
		const probe: Route = {
			method: "GET",
			path: "/live",
			exposure: "probe",
			handle: () => ({ status: 204 }),
		};
		// @ts-expect-error a route is served on the ordinary listener or on a probe listener, no other
		expect({ ...probe, exposure: "admin" } satisfies Route).toBeDefined();
	});

	it("refuses two routes of one method and path at boot", async () => {
		const twice = defineModule({ name: "twice", replicaSafe: false, takes: [] }, (m) => [
			m
				.contribute(routes)
				.by(() => ({ method: "GET", path: "/a", handle: () => ({ status: 204 }) })),
		]);
		const refused = await refusalsOf(boot({}, { modules: [route, twice] }));
		expect(refused).toEqual([
			["http.routes:GET /a", "more than one contribution for the same key"],
		]);
	});
});
