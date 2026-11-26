import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { keyChangePart } from "@mod/passkey-management";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import transparencyStore from "@mod/transparency-store/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

it("declares its space with every guarantee passkey-management needs of its part, retained", async () => {
	const simulated = simulatedStore();
	await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const flows = simulated.declaredSpace("passkey-management-store.flows");
	expect([...flows.guarantees].sort()).toEqual([
		"authenticated",
		"confirmed-reads",
		"durable",
		"no-eviction",
		"replicated",
	]);
	expect(flows.subjectData).toBe("retained");
});

it("binds the key change's part to the flows' space, which the frame store takes", async () => {
	const app = await assemble({
		modules: [storeModule, transparencyStore, wiring],
		config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
		runtime: quietRuntime(),
	});
	const frames = await app.get(frameStore);
	expect(frames.parts).toContain(keyChangePart);
	const unit = { flow: { of: "subject", id: "s1" } } as const;
	const records = [{ part: keyChangePart, name: "preimage" }];
	const read = await frames.read(unit, records);
	const stage = { kind: "keyChange", op: "r1" };
	expect(await frames.write(read, { records: [{ value: stage }] }, read.now + 1000)).toBe(
		"written",
	);
	expect((await frames.read(unit, records)).held).toEqual([stage]);
});

it("boots over a store that does not tell an outside write apart only as the store's setting accepts", async () => {
	const refused = await assemble({
		modules: [storeModule, wiring],
		config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": false }) },
		runtime: quietRuntime(),
	}).then(
		() => "booted",
		(error: unknown) =>
			BootRefused.is(error) ? error.refusals.map((r) => `${r.where}: ${r.reason}`).join("\n") : "",
	);
	expect(refused).toMatch("passkey-management-store.flows");
});
