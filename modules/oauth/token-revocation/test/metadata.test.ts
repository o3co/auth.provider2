import { auditStandIn } from "@mod/audit/testing";
import { authMethods } from "@mod/clients";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import { revocableKinds } from "../src/contract.ts";
import { revocationConfig, revocationModules } from "./serve.ts";

const runtime = quietRuntime();

const refreshKind = defineModule({ name: "refresh-kind", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(revocableKinds).by(() => ({ hint: "refresh_token", revoke: async () => "unknown" })),
]);

const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

/** A deployment reached at `origin`, its access tokens revocable or not. */
const assembly = (revocable: boolean, origin: string, extra: Module[] = []) => ({
	modules: revocationModules(
		tokensStandIn({ revocable }),
		rateLimitStandIn,
		auditStandIn().module,
		reader,
		...extra,
	),
	config: revocationConfig(origin),
	runtime,
});

/** The metadata items with a value of that deployment. */
async function documentOf(revocable: boolean, origin: string, extra: Module[] = []) {
	const app = await assemble(assembly(revocable, origin, extra));
	const items = app.get(published).filter((item) => item.value !== undefined);
	return Object.fromEntries(items.map((item) => [item.name, item.value]));
}

it("publishes where it revokes, as an absolute https URL on the public origin with no fragment [rfc7009-2-c] [rfc7009-2-d]", async () => {
	const document = await documentOf(true, "https://as.example");
	expect(document.revocation_endpoint).toBe("https://as.example/oauth/revoke");
	const url = new URL(document.revocation_endpoint as string);
	expect([url.protocol, url.hash]).toEqual(["https:", ""]);
});

it("publishes revocation only where some token can be revoked", async () => {
	expect(await documentOf(false, "https://as.example")).not.toHaveProperty("revocation_endpoint");
	expect((await documentOf(false, "https://as.example", [refreshKind])).revocation_endpoint).toBe(
		"https://as.example/oauth/revoke",
	);
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

it("publishes how a client authenticates there, a public client too, and the algorithms of signed methods as they take them [rfc8414-2-l] [rfc8414-2-n]", async () => {
	const plain = await documentOf(true, "https://as.example");
	expect(plain.revocation_endpoint_auth_methods_supported).toEqual([
		"client_secret_basic",
		"client_secret_post",
		"none",
	]);
	expect(plain).not.toHaveProperty("revocation_endpoint_auth_signing_alg_values_supported");
	const withSigned = await documentOf(true, "https://as.example", [signed]);
	expect(withSigned.revocation_endpoint_auth_methods_supported).toContain("private_key_jwt");
	expect(withSigned.revocation_endpoint_auth_signing_alg_values_supported).toEqual(["ES256"]);
	// Where revocation is not published, neither is how to authenticate there.
	const unrevocable = await documentOf(false, "https://as.example", [signed]);
	expect(unrevocable).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
	expect(unrevocable).not.toHaveProperty("revocation_endpoint_auth_signing_alg_values_supported");
});

it("takes all its module names, tokens revocable or not, a kind contributed or not", async () => {
	for (const revocable of [true, false])
		for (const extra of [[], [refreshKind]]) {
			const input = assembly(revocable, "https://as.example", extra);
			// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
			expect(
				(await takesUnused(input))["token-revocation"],
				`${revocable} ${extra.length}`,
			).toBeUndefined();
		}
});
