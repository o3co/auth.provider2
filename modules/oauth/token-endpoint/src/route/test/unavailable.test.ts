import { audit } from "@mod/audit";
import clientAllowanceModule from "@mod/client-allowance/module";
import { clientsConfig } from "@mod/clients/testing";
import { listening } from "@mod/http";
import { assemble, defineModule, Unavailable } from "@mod/kernel";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { afterEach, describe, expect, it } from "vitest";
import { basicOf, endpointConfig, endpointModules } from "../../../test/deployment.ts";
import { client, logged, quiet } from "../../../test/served.ts";

let stop = async () => {};
afterEach(() => stop());

describe("token endpoint", () => {
	it("keeps a grant type nothing dispatches to out of the log when it cannot tell, as the client's own input", async () => {
		const down = defineModule({ name: "audit", replicaSafe: true, takes: [] }, (m) => [
			m.provide(audit).by(() => ({
				record: () => {
					throw new Unavailable("audit");
				},
				lost: () => ({}),
			})),
		]);
		const app = await assemble({
			modules: endpointModules(clientAllowanceModule, rateLimitStandIn, down),
			config: { ...endpointConfig(), ...clientsConfig([client("basic", "client_secret_basic")]) },
			runtime: quiet,
		});
		await app.start();
		stop = () => app.stop(1000);
		const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: basicOf("basic", "basic-secret"),
			},
			body: "grant_type=urn%3Atest%3Akept-out",
		});
		expect(res.status).toBe(503);
		expect(logged.lines().at(-1)).toEqual({
			level: "warn",
			event: "http.unavailable",
			fields: { what: "audit", route: "/oauth/token" },
		});
		expect(JSON.stringify(logged.lines().at(-1))).not.toContain("kept-out");
	});
});
