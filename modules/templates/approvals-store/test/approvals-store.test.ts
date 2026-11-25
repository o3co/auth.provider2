import { approvalPart, approvalStore } from "@mod/approvals";
import { approvalStoreContract } from "@mod/approvals/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import transparencyStore from "@mod/transparency-store/module";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const all = ["no-eviction", "durable", "replicated", "confirmed-reads", "authenticated"];

approvalStoreContract("approvals-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	// The composition's clock stands still, so only the test's own moves run a lifetime out.
	const now = Date.UTC(2026, 0, 1);
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		store: app.get(approvalStore),
		advance: (ms) => simulated.shiftClock(ms),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});

describe("approvals-store", () => {
	it("declares the statements' and the flows' spaces with every guarantee approvals and the frames need", async () => {
		const simulated = simulatedStore();
		await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		for (const name of ["approvals-store.statements", "approvals-store.flows"]) {
			const declared = simulated.declaredSpace(name);
			expect([...declared.guarantees].sort()).toEqual([...all].sort());
			expect(declared.subjectData).toBe("retained");
		}
	});

	it("binds approvals' part to the flows' space, which the frame store takes", async () => {
		const app = await assemble({
			modules: [storeModule, transparencyStore, wiring],
			config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
			runtime: quietRuntime(),
		});
		const frames = await app.get(frameStore);
		expect(frames.parts).toContain(approvalPart);
		const unit = { flow: { of: "subject", id: "s1" } } as const;
		const records = [{ part: approvalPart, name: "state" }];
		const read = await frames.read(unit, records);
		const state = { approvals: {}, consumed: ["statement:x"] };
		expect(await frames.write(read, { records: [{ value: state }] }, read.now + 1000)).toBe(
			"written",
		);
		expect((await frames.read(unit, records)).held).toEqual([state]);
	});

	it("boots over a store that does not tell an outside write apart only as the store's setting accepts", async () => {
		const refused = await assemble({
			modules: [storeModule, wiring],
			config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": false }) },
			runtime: quietRuntime(),
		}).then(
			() => "booted",
			(error: unknown) =>
				BootRefused.is(error)
					? error.refusals.map((r) => `${r.where}: ${r.reason}`).join("\n")
					: "",
		);
		expect(refused).toMatch(/approvals-store\.statements/);
		expect(refused).toMatch(/approvals-store\.flows/);
	});
});
