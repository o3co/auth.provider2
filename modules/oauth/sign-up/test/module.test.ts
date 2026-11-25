import { approvals } from "@mod/approvals";
import { type SignUpOffer, signUpOffers } from "@mod/authorize";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type ContinueStage, continueStages, signUpCreations } from "@mod/passkey-management";
import { rateLimit } from "@mod/rate-limit";
import { users } from "@mod/users";
import { describe, expect, it } from "vitest";
import signUp from "../src/module.ts";

const seen = contract<{
	readonly stages: readonly ContinueStage[];
	readonly offers: readonly SignUpOffer[];
}>("test.seen");

const fakes = (ledger: object) =>
	defineModule({ name: "fakes", replicaSafe: true, takes: [continueStages, signUpOffers] }, (m) => [
		// A T no longer issued: what the stage answers, past approvals.
		m
			.provide(approvals)
			.by(() => ({ continueSignUp: async () => ({ kind: "refused", reason: "used" }) }) as never),
		m.provide(users).by(() => ledger as never),
		m.provide(signUpCreations).by(() => ({}) as never),
		m.provide(rateLimit).by(() => ({}) as never),
		m.provide(seen).by(async (c) => ({
			stages: await c.collect(continueStages),
			offers: await c.collect(signUpOffers),
		})),
	]);

const boot = (ledger: object) =>
	assemble({
		modules: [fakes(ledger), signUp],
		config: { ...kernelConfig(), "sign-up": {} },
		runtime: quietRuntime(),
	});

describe("sign-up, composed", () => {
	it("offers a sign-up to authorize, and continues `/continue`'s stage `sign-up` through approvals", async () => {
		const app = await boot({ createIdentifierless: async () => ({ subject: "s" }) });
		const { stages, offers } = await app.get(seen);
		expect(offers).toEqual([{ by: "sign-up" }]);
		expect(stages.map((s) => s.stage)).toEqual(["sign-up"]);
		const ask = { stage: "sign-up", source: "s", statement: "t", hash: "h", seq: 1 } as const;
		expect(await stages[0]?.continue({ ...ask, body: "{}", signature: "sig" })).toEqual({
			kind: "refused",
			reason: "used",
		});
	});

	it("refuses boot where the users' ledger makes no subjects without an identifier", async () => {
		const refused = await boot({}).then(
			() => [],
			(error: unknown) =>
				BootRefused.is(error) ? error.refusals.map((r) => r.reason) : [String(error)],
		);
		expect(refused).toEqual([expect.stringMatching(/makes no subjects without an identifier/)]);
	});
});
