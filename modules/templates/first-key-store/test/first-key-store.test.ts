import { firstKeyNonces, firstKeyTokens } from "@mod/first-key";
import { firstKeyStoreContract } from "@mod/first-key/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

firstKeyStoreContract("first-key-store on records, on a simulated replicated store", async () => {
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
});

it("declares its spaces with every guarantee first-key needs: the nonces with no subject's data, the tokens retained", async () => {
	const simulated = simulatedStore();
	await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const all = ["authenticated", "confirmed-reads", "durable", "no-eviction", "replicated"];
	const nonces = simulated.declaredSpace("first-key-store.nonces");
	const tokens = simulated.declaredSpace("first-key-store.tokens");
	for (const space of [nonces, tokens]) expect([...space.guarantees].sort()).toEqual(all);
	expect(nonces.subjectData).toBe("none");
	expect(tokens.subjectData).toBe("retained");
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
	for (const space of ["nonces", "tokens"]) expect(refused).toMatch(`first-key-store.${space}`);
});
