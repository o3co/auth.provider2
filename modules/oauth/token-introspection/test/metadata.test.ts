import { auditStandIn } from "@mod/audit/testing";
import { authMethods } from "@mod/clients";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { promiseNames, type Stance, stances } from "@mod/promises";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { expect, it } from "vitest";
import { introspectionConfig, introspectionModules } from "./serve.ts";

const runtime = quietRuntime();

const published = contract<readonly MetadataItem[]>("published");
const declared = contract<readonly Stance[]>("declared");
const reader = defineModule(
	{ name: "reader", replicaSafe: true, takes: [metadata, stances] },
	(m) => [
		m.provide(published).by((c) => c.collect(metadata)),
		m.provide(declared).by((c) => c.collect(stances)),
	],
);

/** A deployment reached at `origin`. */
const assembly = (origin: string, extra: Module[] = []) => ({
	modules: introspectionModules(rateLimitStandIn, auditStandIn().module, reader, ...extra),
	config: introspectionConfig(origin),
	runtime,
});

/** The metadata items with a value of that deployment. */
async function documentOf(origin: string, extra: Module[] = []) {
	const app = await assemble(assembly(origin, extra));
	const items = app.get(published).filter((item) => item.value !== undefined);
	return Object.fromEntries(items.map((item) => [item.name, item.value]));
}

it("publishes where it introspects, as an absolute https URL on the public origin with no fragment [rfc7662-2-a]", async () => {
	const document = await documentOf("https://as.example");
	expect(document.introspection_endpoint).toBe("https://as.example/oauth/introspect");
	const url = new URL(document.introspection_endpoint as string);
	expect([url.protocol, url.hash]).toEqual(["https:", ""]);
});

/** A signed method, as client-assertion contributes one. */
const signed = defineModule({ name: "signed-method", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(authMethods).by(() => ({
		name: "private_key_jwt",
		assertion: true,
		signingAlgorithms: ["ES256"],
		claimed: () => undefined,
		verify: async () => undefined,
	})),
]);

it("publishes how a client authenticates there, never as a public client, and the algorithms of signed methods as they take them [rfc8414-2-l] [rfc8414-2-n]", async () => {
	const plain = await documentOf("https://as.example");
	expect(plain.introspection_endpoint_auth_methods_supported).toEqual([
		"client_secret_basic",
		"client_secret_post",
	]);
	expect(plain).not.toHaveProperty("introspection_endpoint_auth_signing_alg_values_supported");
	const withSigned = await documentOf("https://as.example", [signed]);
	expect(withSigned.introspection_endpoint_auth_methods_supported).toContain("private_key_jwt");
	expect(withSigned.introspection_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
});

it("stands breaking both promises a compromised Front must not break, naming why and no setting", async () => {
	const app = await assemble(assembly("https://as.example"));
	const own = app.get(declared).filter((stance) => stance.by === "token-introspection");
	expect(own.map((stance) => [stance.promise, stance.holds, stance.setting])).toEqual([
		[promiseNames.newAuthorization, false, undefined],
		[promiseNames.clientToken, false, undefined],
	]);
	for (const stance of own) expect(stance.reason).toContain("bound to neither the token");
});

it("takes all its module names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect(
		(await takesUnused(assembly("https://as.example")))["token-introspection"],
	).toBeUndefined();
});
