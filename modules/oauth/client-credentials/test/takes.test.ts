import { clientAssertion } from "@mod/client-assertion";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { rateLimit } from "@mod/rate-limit";
import { senderBinding } from "@mod/sender-binding";
import { expect, it } from "vitest";
import clientCredentials from "../src/module.ts";

const collected = contract<readonly unknown[]>("test.grants");
/** What it takes, beside it, with a binding kind writing `writes` (none when undefined). */
const beside = (writes?: string) =>
	defineModule({ name: "beside", replicaSafe: true, takes: [grants] }, (m) => [
		m.provide(issuer).by(() => ({ url: "https://as.example" }) as never),
		m.provide(clientAssertion).by(() => ({}) as never),
		m.provide(rateLimit).by(() => ({}) as never),
		m
			.provide(senderBinding)
			.by(() => ({ tokenTypeOf: (m: string) => (m === writes ? "DPoP" : undefined) }) as never),
		m.provide(collected).by((c) => c.collect(grants)),
	]);

it("takes the issuer, the client's keys, the counts and the binding kinds, and nothing it names goes untaken", async () => {
	const input = { modules: [beside("jkt"), clientCredentials], config: kernelConfig() };
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["client-credentials"]).toBeUndefined();
});

it("refuses boot where no binding kind writes a DPoP proof's key, as every token it issues is bound so", async () => {
	const refused = await assemble({
		modules: [beside(), clientCredentials],
		config: kernelConfig(),
	}).catch((e: unknown) => e);
	expect(BootRefused.is(refused) && refused.refusals).toEqual([
		{
			where: "client-credentials",
			reason: "no binding kind writes jkt: compose dpop, which binds the client's token to its key",
		},
	]);
});

it("counts sixty requests a minute for each client, and suspends none, unless set", async () => {
	expect(clientCredentials.section?.parse({})).toEqual({
		lifetime: 300,
		requests: 60,
		suspended: [],
	});
	for (const not of [0, 100_001, 1.5, "60"])
		expect(clientCredentials.section?.safeParse({ requests: not }).success, String(not)).toBe(
			false,
		);
	expect(clientCredentials.section?.parse({ suspended: ["svc"] })).toEqual({
		lifetime: 300,
		requests: 60,
		suspended: ["svc"],
	});
});

it("lets its token live five minutes unless set, from a minute to the fifteen authority-rules lets one live", () => {
	const parse = (lifetime: unknown) => clientCredentials.section?.safeParse({ lifetime });
	expect(parse("1m")?.data).toMatchObject({ lifetime: 60 });
	expect(parse("15m")?.data).toMatchObject({ lifetime: 900 });
	for (const not of ["59s", "15m1s", "16m", 300])
		expect(parse(not)?.success, String(not)).toBe(false);
});
