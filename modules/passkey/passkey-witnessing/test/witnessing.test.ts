import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { type PasskeyWitnessing, passkeyWitnessing } from "@mod/passkeys";
import { describe, expect, it } from "vitest";
import witnessingModule from "../src/module.ts";
import { witnessingOver } from "../src/witnessing.ts";

const seen = contract<readonly PasskeyWitnessing[]>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [passkeyWitnessing] },
	(m) => [m.provide(seen).by((c) => c.collect(passkeyWitnessing))],
);

/** The witnessing over a witness in memory. */
function over() {
	const stand = passkeyWitnessStandIn();
	return { ...stand, witnessing: witnessingOver(stand.witness) };
}

describe("passkey-witnessing", () => {
	it("marks for a key generation, unless a mark is set", async () => {
		const { witnessing, marks } = over();
		expect(await witnessing.marked("s")).toBe(false);
		await witnessing.mark("s", 2);
		expect(await witnessing.marked("s")).toBe(true);
		await witnessing.mark("s", 3);
		await witnessing.mark("s", 2);
		expect(marks.get("s")).toBe("generation-2");
	});

	it("withdraws only a mark of a generation before the one given", async () => {
		const { witnessing } = over();
		await witnessing.withdraw("s", 1);
		await witnessing.mark("s", 2);
		await witnessing.withdraw("s", 2);
		expect(await witnessing.marked("s")).toBe(true);
		await witnessing.withdraw("s", 3);
		expect(await witnessing.marked("s")).toBe(false);
	});

	it("withdraws a mark of a generation before set while it withdrew, reading again", async () => {
		const { witnessing, witness, next } = over();
		await witnessing.mark("s", 1);
		next.beforeWithdraw = () => {
			// A late mark of a generation before lands once the first is gone.
			queueMicrotask(() => void witness.enroll("s", "generation-0"));
		};
		await witnessing.withdraw("s", 2);
		expect(await witnessing.marked("s")).toBe(false);
	});

	it("answers unavailable for a mark of no generation, removing nothing", async () => {
		const { witnessing, witness } = over();
		expect(await witness.enroll("s", "another")).toBe(true);
		await expect(witnessing.withdraw("s", 5)).rejects.toSatisfy(isUnavailable);
		expect(await witness.markedWith("s")).toBe("another");
	});

	it("passes a witness that cannot answer on as unavailable, never a refusal", async () => {
		const { witnessing, failing } = over();
		failing.read = 1;
		await expect(witnessing.marked("s")).rejects.toSatisfy(isUnavailable);
		failing.enroll = 1;
		await expect(witnessing.mark("s", 1)).rejects.toSatisfy(isUnavailable);
		await witnessing.mark("s", 1);
		failing.markedWith = 1;
		await expect(witnessing.withdraw("s", 2)).rejects.toSatisfy(isUnavailable);
		failing.withdraw = 1;
		await expect(witnessing.withdraw("s", 2)).rejects.toSatisfy(isUnavailable);
		await witnessing.withdraw("s", 2);
		expect(await witnessing.marked("s")).toBe(false);
	});

	it("refuses a generation that is no whole number at or above zero", async () => {
		const { witnessing } = over();
		for (const generation of [-1, 1.5, Number.NaN]) {
			await expect(witnessing.mark("s", generation)).rejects.toBeInstanceOf(TypeError);
			await expect(witnessing.withdraw("s", generation)).rejects.toBeInstanceOf(TypeError);
		}
	});

	it("contributes the witnessing over the one witness composed, and refuses boot with none or two", async () => {
		const stand = passkeyWitnessStandIn();
		const app = await assemble({
			modules: [stand.module, witnessingModule, collecting],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		const [witnessing, ...more] = app.get(seen);
		expect(more).toEqual([]);
		await witnessing?.mark("s", 0);
		expect(stand.marks.get("s")).toBe("generation-0");
		for (const witnesses of [[], [stand.module, passkeyWitnessStandIn("another").module]]) {
			const refused = await assemble({
				modules: [...witnesses, witnessingModule],
				config: kernelConfig(),
				runtime: quietRuntime(),
			}).catch((e: unknown) => e);
			expect(refused).toBeInstanceOf(BootRefused);
			expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["passkey-witnessing"]);
		}
	});
});
