import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { pushedRequests } from "@mod/par";
import { pushedRequestsContract } from "@mod/par/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// The composition's clock stands still: the store's time moves by `advance` alone, however long the test takes.
const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

pushedRequestsContract("par-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	return { pushed: await app.get(pushedRequests), advance: (ms) => simulated.shiftClock(ms) };
});

it("declares the pushed requests' space with every guarantee par needs, as retained", async () => {
	const simulated = simulatedStore();
	await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const declared = simulated.declaredSpace("par-store.pushed");
	expect([...declared.guarantees].sort()).toEqual([
		"authenticated",
		"confirmed-reads",
		"no-eviction",
		"replicated",
	]);
	expect(declared.subjectData).toBe("retained");
});
