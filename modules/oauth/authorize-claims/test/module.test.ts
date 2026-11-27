import { type RequestClaims, requestClaims } from "@mod/authorize";
import { claimsSelections } from "@mod/claims-selection";
import { codes } from "@mod/code-grant";
import { type MetadataItem, metadata } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { idTokenHints } from "@mod/oidc";
import { expect, it } from "vitest";
import authorizeClaims from "../src/module.ts";

const seen = contract<{
	readonly readers: readonly RequestClaims[];
	readonly items: readonly MetadataItem[];
}>("test.seen");

/** claims-selection and code-grant as fakes; what reads `requestClaims` as authorize does, and the metadata as issuer does. */
const fakes = (idTokens: boolean, hints = false) =>
	defineModule({ name: "fakes", replicaSafe: true, takes: [requestClaims, metadata] }, (m) => [
		...(hints
			? [m.provide(idTokenHints).by(() => ({ subjectOf: async () => ({ subject: "alice" }) }))]
			: []),
		m.provide(claimsSelections).by(() => ({}) as never),
		m.provide(codes).by(() => ({ issuesIdTokens: () => idTokens }) as never),
		m.provide(seen).by(async (c) => ({
			readers: await c.collect(requestClaims),
			items: await c.collect(metadata),
		})),
	]);
const boot = (idTokens: boolean, hints = false) =>
	assemble({
		modules: [fakes(idTokens, hints), authorizeClaims],
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

it("reads an id_token_hint through oidc's reader where it is composed, and none where it is not", async () => {
	const [withOidc] = (await boot(true, true)).get(seen).readers;
	expect(await withOidc?.hint?.("h.p.s", "c1")).toEqual({ subject: "alice" });
	const [without] = (await boot(true)).get(seen).readers;
	expect(without?.hint).toBeUndefined();
});
