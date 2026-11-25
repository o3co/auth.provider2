import { type RequestClaims, requestClaims } from "@mod/authorize";
import { claimsSelections } from "@mod/claims-selection";
import { codes } from "@mod/code-grant";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import authorizeClaims from "../src/module.ts";

const seen = contract<{
	readonly readers: readonly RequestClaims[];
	readonly items: readonly MetadataItem[];
}>("test.seen");

/** claims-selection and code-grant as fakes; what reads `requestClaims` as authorize does, and the metadata as issuer does. */
const fakes = (idTokens: boolean) =>
	defineModule({ name: "fakes", replicaSafe: true, takes: [requestClaims, metadata] }, (m) => [
		m.provide(claimsSelections).by(() => ({}) as never),
		m.provide(codes).by(() => ({ issuesIdTokens: () => idTokens }) as never),
		m.provide(seen).by(async (c) => ({
			readers: await c.collect(requestClaims),
			items: await c.collect(metadata),
		})),
	]);
const boot = (idTokens: boolean) =>
	assemble({
		modules: [fakes(idTokens), authorizeClaims],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});

it("gives authorize the one reading of a request's claims, and says the parameter is supported", async () => {
	const { readers, items } = (await boot(true)).get(seen);
	expect(readers).toHaveLength(1);
	expect(readers[0]?.refusal({ id_token: { email: null } }, false)).toMatch(/openid/);
	expect(items).toEqual([{ name: "claims_parameter_supported", value: true }]);
});

it("leaves the parameter out of the metadata where no ID token is made, as authorize refuses every OpenID request", async () => {
	const { items } = (await boot(false)).get(seen);
	expect(items).toEqual([{ name: "claims_parameter_supported", value: undefined }]);
});
