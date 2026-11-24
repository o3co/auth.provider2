import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientSources } from "@mod/clients";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { assemble, BootRefused, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { describe, expect, it } from "vitest";
import { clientTokensModule, endpointConfig, endpointModules } from "../../../test/deployment.ts";

const quiet = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});

/** A deployment of the endpoint and `modules`, registering a client allowed each list of `grants`. */
const boot = (modules: Module[], ...grants: string[][]) =>
	assemble({
		// The endpoint as the helper composes it, but for the client credentials grant, which `modules` may add.
		modules: [
			...endpointModules(rateLimitStandIn, auditStandIn().module, clientAllowanceModule).filter(
				(module) => module !== clientTokensModule,
			),
			...modules,
		],
		config: {
			...endpointConfig(),
			...clientsConfig(
				grants.map((allowed, i) =>
					confidentialClient({ id: `c${i}`, sections: allowancesFor({ grants: allowed }) }),
				),
			),
		},
		runtime: quiet,
	});
/** The boot's refusals, none where it boots; any other error is thrown, so it never reads as a boot. */
const refusals = (deployment: Promise<unknown>) =>
	deployment.then(
		() => [],
		(error) => {
			if (!BootRefused.is(error)) throw error;
			return error.refusals.map((r) => `${r.where}: ${r.reason}`);
		},
	);

describe("a registered client allowed a grant nothing composed serves", () => {
	it("refuses boot at the grant's place in the client's list, naming the module `grants`' index names, or none", async () => {
		const none = "no composed module serves this grant: compose the module that serves it";
		expect(
			await refusals(boot([], ["authorization_code"], [], ["refresh_token", "urn:x:own"])),
		).toEqual(
			[
				"0.sections.client-allowance.grants.0",
				"2.sections.client-allowance.grants.0",
				"2.sections.client-allowance.grants.1",
			].map((at) => `clients.registered.${at}: ${none}, or take it out of the client's grants`),
		);
	});

	it("boots once a module serving the grant is composed", async () => {
		expect(await refusals(boot([], ["client_credentials"]))).toHaveLength(1);
		expect(await refusals(boot([clientTokensModule], ["client_credentials"]))).toEqual([]);
	});

	it("names no module for a type that is a name every object has", async () => {
		const unknown = "no composed module serves this grant: compose the module that serves it";
		expect(
			await refusals(boot([], ["constructor", "__proto__", "toString", "hasOwnProperty"])),
		).toEqual(
			[0, 1, 2, 3].map(
				(j) =>
					`clients.registered.0.sections.client-allowance.grants.${j}: ${unknown}, or take it out of the client's grants`,
			),
		);
	});

	it("never names the client's id or the grant type itself", async () => {
		const told = (await refusals(boot([], ["urn:x:secret-name"]))).join();
		expect(told).not.toMatch(/c0|urn:x:secret-name/);
	});
});

describe("a client a source lists allowed a grant nothing composed serves", () => {
	/** A source listing, and finding, one public client allowed each list of `grants`. */
	const listing = (...allowed: string[][]) => {
		const records = allowed.map((grants, i) => ({
			id: `s${i}`,
			kind: "public" as const,
			method: "none",
			sections: allowancesFor({ grants }),
		}));
		return defineModule({ name: "listing", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(clientSources).by(() => ({
				find: async (id: string) => records.find((record) => record.id === id),
				listed: async () => records,
			})),
		]);
	};
	const told = (server: string) =>
		`clients.sources: a client a source lists is allowed a grant no composed module serves: compose ${server}, or take it out of the client's grants where its source keeps them`;

	it("refuses boot once for each module to compose, naming no client and no grant type", async () => {
		const listed = listing(["client_credentials"], ["client_credentials", "urn:x:secret-name"]);
		expect(await refusals(boot([listed]))).toEqual([
			told("client-credentials"),
			told("the module that serves it"),
		]);
	});

	it("boots once a module serving it is composed", async () => {
		expect(await refusals(boot([clientTokensModule, listing(["client_credentials"])]))).toEqual([]);
	});
});
