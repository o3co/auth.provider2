import { jarReservations } from "@mod/authorize";
import { jarReservationsContract } from "@mod/authorize/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

jarReservationsContract("authorize-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	return {
		reservations: await app.get(jarReservations),
		advance: (ms) => simulated.shiftClock(ms),
	};
});

it("declares the reservations' space with every guarantee authorize needs, and no subject's data", async () => {
	const simulated = simulatedStore();
	await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const declared = simulated.declaredSpace("authorize-store.reservations");
	expect([...declared.guarantees].sort()).toEqual(
		["authenticated", "confirmed-reads", "durable", "no-eviction", "replicated"].sort(),
	);
	expect(declared.subjectData).toBe("none");
});
