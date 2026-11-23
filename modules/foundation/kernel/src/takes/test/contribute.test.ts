import { describe, expect, it } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, extensionPoint, kernelConfig } from "../../contract.ts";

const single = kernelConfig();

describe("a contract whose takers must contribute to a point", () => {
	const stances = extensionPoint<string>("promises.stances", { multiplicity: "many" });
	const sign = contract<string>("keys.sign", { takersContribute: stances });
	const keys = defineModule({ name: "keys", replicaSafe: true, takes: [] }, (m) => [
		m.provide(sign).by(() => "signed"),
	]);

	it("refuses a taker that contributes nothing to the point", async () => {
		const refusals = await refusalsOf(
			assemble({
				modules: [keys, defineModule({ name: "tokens", replicaSafe: true, takes: [sign] })],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{
				where: "tokens",
				reason: "keys.sign is taken only by a module that contributes to promises.stances",
			},
		]);
	});

	it("lets a taker that contributes to the point build", async () => {
		const app = await assemble({
			modules: [
				keys,
				defineModule({ name: "tokens", replicaSafe: true, takes: [sign] }, (m) => [
					m.contribute(stances).by(() => "tokens holds the promise"),
				]),
			],
			config: single,
		});
		expect(app.get(sign)).toBe("signed");
	});

	it("holds an optional take of such a contract to the same rule", async () => {
		const quiet = contract<string>("keys.quiet", { optional: true, takersContribute: stances });
		const { optional } = await import("../../contract.ts");
		const refusals = await refusalsOf(
			assemble({
				modules: [defineModule({ name: "tokens", replicaSafe: true, takes: [optional(quiet)] })],
				config: single,
			}),
		);
		expect(refusals).toEqual([
			{
				where: "tokens",
				reason: "keys.quiet is taken only by a module that contributes to promises.stances",
			},
		]);
	});
});
