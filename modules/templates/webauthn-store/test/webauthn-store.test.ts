import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { passkeyPart, passkeyStore } from "@mod/passkeys";
import { passkeyStoreContract } from "@mod/passkeys/testing";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import transparencyStore from "@mod/transparency-store/module";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const all = ["no-eviction", "durable", "replicated", "confirmed-reads", "authenticated"];

passkeyStoreContract("webauthn-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	return app.get(passkeyStore);
});

describe("webauthn-store", () => {
	it("declares the credentials' and the keys' spaces with every guarantee passkeys and the frames need", async () => {
		const simulated = simulatedStore();
		await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		for (const name of ["webauthn-store.credentials", "webauthn-store.keys"]) {
			const declared = simulated.declaredSpace(name);
			expect([...declared.guarantees].sort()).toEqual([...all].sort());
			expect(declared.subjectData).toBe("retained");
		}
	});

	it("binds passkeys' part to the keys' space, which the frame store takes", async () => {
		const app = await assemble({
			modules: [storeModule, transparencyStore, wiring],
			config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
			runtime: quietRuntime(),
		});
		const frames = await app.get(frameStore);
		expect(frames.parts).toContain(passkeyPart);
		const unit = { flow: { of: "subject", id: "s1" } } as const;
		const records = [{ part: passkeyPart, name: "keys" }];
		const read = await frames.read(unit, records);
		expect(
			await frames.write(
				read,
				{ records: [{ value: { keyGeneration: 0, keys: {} } }] },
				read.now + 1000,
			),
		).toBe("written");
		expect((await frames.read(unit, records)).held).toEqual([{ keyGeneration: 0, keys: {} }]);
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
		expect(refused).toMatch(/webauthn-store\.credentials/);
		expect(refused).toMatch(/webauthn-store\.keys/);
	});
});
