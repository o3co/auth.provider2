import { listening, routes } from "@mod/http";
import http from "@mod/http/module";
import httpOps from "@mod/http-ops/module";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { afterEach, describe, expect, it } from "vitest";
import inProcess from "../src/module.ts";

const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0)) await stop();
});

const coreRoute = defineModule({ name: "core-route", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "POST",
		path: "/oauth/token",
		crossSite: "a client's server calls it",
		unlimited: "test",
		handle: (request) => ({
			status: 200,
			body: { json: { code: request.fields.single("code") ?? "" } },
		}),
	})),
]);

const boot = (required: readonly string[] = []) =>
	assemble({
		modules: [http, inProcess, promisesModule, httpOps, coreRoute],
		config: { ...kernelConfig(), http: { port: 0 }, promises: { required } },
		runtime: quietRuntime(),
	});

describe("in-process", () => {
	it("serves every route on the one listener, the Core's and the probes alike, read from the request's bytes", async () => {
		const app = await boot();
		await app.start();
		stops.push(() => app.stop(1000));
		const url = `http://127.0.0.1:${app.get(listening).port()}`;
		const token = await fetch(`${url}/oauth/token`, {
			method: "POST",
			body: new URLSearchParams({ code: "abc" }),
		});
		expect([token.status, await token.json()]).toEqual([200, { code: "abc" }]);
		expect((await fetch(`${url}/readyz`)).status).toBe(200);
		expect((await fetch(`${url}/nowhere`)).status).toBe(404);
	});

	it("stands breaking the two promises a compromised Front must not break, naming why", async () => {
		const app = await boot();
		const judged = app.get(promises).judgment();
		const of = (name: string) => judged.find((j) => j.promise === name);
		for (const name of [promiseNames.newAuthorization, promiseNames.clientToken]) {
			expect(of(name)).toMatchObject({
				held: false,
				breaking: [{ by: "in-process", reason: expect.stringContaining("the Front's process") }],
			});
		}
		expect(of(promiseNames.coreContained)?.breaking).toEqual([]);
		await app.stop(1000);
	});

	it("is refused where the deployment requires either", async () => {
		const refused = await boot([promiseNames.newAuthorization]).catch((e: unknown) => e);
		expect(BootRefused.is(refused) && refused.refusals.map((r) => r.where)).toEqual([
			"promises.required.0",
		]);
	});
});
