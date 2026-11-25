import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { firstKeyNonces, firstKeyTokens, keyChangePart } from "@mod/passkey-management";
import { firstKeyStoreContract } from "@mod/passkey-management/testing";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import transparencyStore from "@mod/transparency-store/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

firstKeyStoreContract(
	"passkey-management-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		// The composition's clock stands still, so only the test's own moves run a lifetime out.
		const now = Date.UTC(2026, 0, 1);
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime: quietRuntime({ clock: { now: () => now } }),
		});
		return {
			nonces: await app.get(firstKeyNonces),
			tokens: await app.get(firstKeyTokens),
			advance: (ms) => simulated.shiftClock(ms),
		};
	},
);

it("declares its spaces with every guarantee passkey-management and the frames need: the nonces with no subject's data, the others retained", async () => {
	const simulated = simulatedStore();
	await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const all = ["authenticated", "confirmed-reads", "durable", "no-eviction", "replicated"];
	const nonces = simulated.declaredSpace("passkey-management-store.nonces");
	const tokens = simulated.declaredSpace("passkey-management-store.tokens");
	const flows = simulated.declaredSpace("passkey-management-store.flows");
	for (const space of [nonces, tokens, flows]) expect([...space.guarantees].sort()).toEqual(all);
	expect(nonces.subjectData).toBe("none");
	expect(tokens.subjectData).toBe("retained");
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
	for (const space of ["nonces", "tokens", "flows"])
		expect(refused).toMatch(`passkey-management-store.${space}`);
});
