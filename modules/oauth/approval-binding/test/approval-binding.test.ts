import { type StatementItems, statementItems } from "@mod/approvals";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const declared = contract<readonly StatementItems[]>("test.declared");

it("declares the authorization's dpop_jkt, and no other item", async () => {
	const reader = defineModule(
		{ name: "reader", replicaSafe: true, takes: [statementItems] },
		(m) => [m.provide(declared).by((c) => c.collect(statementItems))],
	);
	const app = await assemble({
		modules: [reader, bridge],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	expect(await app.get(declared)).toEqual([
		{ purpose: "authorization", names: ["dpop_jkt"], by: "approval-binding" },
	]);
});
