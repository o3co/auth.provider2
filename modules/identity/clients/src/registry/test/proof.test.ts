import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import secretHashModule from "@mod/secret-hash/module";
import { expect, it } from "vitest";
import {
	type AuthMethod,
	authMethods,
	type ClientRecord,
	clientSources,
	clients,
} from "../../contract.ts";
import clientsModule from "../../module.ts";

const asked = (): HttpRequest =>
	testRequest({ method: "POST", form: new Map([["x_cred", ["c1"]]]) });

/** Clients with one method claiming `c1` and verifying as `verify` answers, and a source of `c1`. */
async function boot(
	verify: AuthMethod["verify"],
	record: Partial<ClientRecord> = {},
	method: Partial<AuthMethod> = {},
) {
	const beside = defineModule({ name: "beside", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(authMethods).by(() => ({
			name: "x_method",
			claimed: (request) => (request.form.has("x_cred") ? "c1" : undefined),
			verify,
			...method,
		})),
		m.contribute(clientSources).by(() => ({
			find: async (id) =>
				id === "c1"
					? { id, kind: "confidential", method: "x_method", sections: {}, ...record }
					: undefined,
		})),
	]);
	const app = await assemble({
		modules: [clientsModule, secretHashModule, beside],
		config: { ...kernelConfig(), clients: { registered: [] } },
	});
	return app.get(clients);
}

it("carries what the method verified, unread, in the authenticated answer; none verified is bad credentials", async () => {
	const proof = { key: "k" };
	expect(await (await boot(async () => ({ proof }))).authenticate(asked())).toMatchObject({
		kind: "authenticated",
		proof,
	});
	const nothing = await (await boot(async () => ({}))).authenticate(asked());
	expect(nothing.kind === "authenticated" && "proof" in nothing).toBe(false);
	expect(await (await boot(async () => undefined)).authenticate(asked())).toMatchObject({
		kind: "refused",
		reason: "bad_credentials",
	});
});

it("says it verified an assertion only where its method authenticates by one, whatever proof another's gives", async () => {
	const proof = { key: "k" };
	const byAssertion = { assertion: true, signingAlgorithms: ["ES256"] } as const;
	expect(await (await boot(async () => ({}), {}, byAssertion)).authenticate(asked())).toMatchObject(
		{ kind: "authenticated", assertion: true },
	);
	const other = await (await boot(async () => ({ proof }))).authenticate(asked());
	expect(other).toMatchObject({ kind: "authenticated", proof });
	expect("assertion" in other).toBe(false);
});

it("says the registry version a source's record came from, and none where it names none", async () => {
	const versioned = await (await boot(async () => ({}), { version: 7 })).find("c1");
	expect(versioned?.version).toBe(7);
	expect("version" in ((await (await boot(async () => ({}))).find("c1")) ?? {})).toBe(false);
	for (const version of [0, 1.5, "7"]) {
		const wrong = await boot(async () => ({}), { version } as never);
		expect(await wrong.find("c1"), String(version)).toBeUndefined();
	}
});
