import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { familyRecords, type StoredFamilyRecord } from "@mod/refresh";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const value = (n: number) => ({ format: 1, n }) as unknown as StoredFamilyRecord;

for (const phase of ["reader", "indexed"] as const) {
	it(`keeps refresh's records on subject-records, created once, changed from what they hold, erased by subject (${phase})`, async () => {
		const simulated = simulatedStore();
		if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const records = app.get(familyRecords);
		expect(await records.create("f.r-1", value(1), 60_000, "alice")).toBe("created");
		expect(await records.create("f.r-1", value(2), 60_000, "alice")).toBe("exists");
		expect(await records.read("f.r-1")).toEqual(value(1));
		expect(await records.change("f.r-1", () => ({ value: value(3) }))).toEqual({
			before: value(1),
			after: value(3),
		});
		expect(await records.change("f.none", () => ({ value: value(4) }))).toBeUndefined();
		expect(typeof records.erase === typeof records.migrate).toBe(true);
		simulated.shiftClock(60_001);
		expect(await records.read("f.r-1")).toBeUndefined();
	});
}

it("stops a record created past its subject's erasure, where erasure is on", async () => {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const records = app.get(familyRecords);
	await records.create("f.r-1", value(1), 60_000, "erin");
	await records.erase?.("erin", new AbortController().signal);
	expect(await records.read("f.r-1")).toBeUndefined();
	expect(await records.create("f.r-2", value(2), 60_000, "erin")).toBe("erased");
});
