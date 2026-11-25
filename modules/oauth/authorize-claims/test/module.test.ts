import { type RequestClaims, requestClaims } from "@mod/authorize";
import { claimsSelections } from "@mod/claims-selection";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import authorizeClaims from "../src/module.ts";

const seen = contract<readonly RequestClaims[]>("test.seen");

/** claims-selection's records as a fake, and what reads `requestClaims` as authorize does. */
const fakes = defineModule({ name: "fakes", replicaSafe: true, takes: [requestClaims] }, (m) => [
	m.provide(claimsSelections).by(() => ({}) as never),
	m.provide(seen).by((c) => c.collect(requestClaims)),
]);

it("gives authorize the one reading of a request's claims", async () => {
	const app = await assemble({
		modules: [fakes, authorizeClaims],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const readers = app.get(seen);
	expect(readers).toHaveLength(1);
	expect(readers[0]?.refusal({ id_token: { email: null } }, false)).toMatch(/openid/);
});
