import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { familiesPart, familyRecords, type StoredFamilyRecord } from "@mod/refresh";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import transparencyStore from "@mod/transparency-store/module";
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

it("erases a subject's rooted lists with its other records, so none names its families after", async () => {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const records = app.get(familyRecords);
	// A rooted list, as refresh names one (`s.<bucket>.<subject>`): a subject's families by their root key.
	const list = "s.20833.erin";
	expect(await records.create(list, value(1), 172_920_000, "erin")).toBe("created");
	expect(await records.create("f.r-1", value(2), 60_000, "erin")).toBe("created");
	expect(await records.create("s.20833.frank", value(3), 172_920_000, "frank")).toBe("created");
	await records.erase?.("erin", new AbortController().signal);
	expect(await records.read(list)).toBeUndefined();
	expect(await records.read("f.r-1")).toBeUndefined();
	// Another subject's list stays; one made again for the erased subject is stopped.
	expect(await records.read("s.20833.frank")).toEqual(value(3));
	expect(await records.create(list, value(4), 172_920_000, "erin")).toBe("erased");
});

it("binds refresh's part of a subject's flow to the flows' space, which the frame store takes", async () => {
	const simulated = simulatedStore();
	await assemble({ modules: [simulated.module, wiring], config: kernelConfig(), runtime });
	const declared = simulated.declaredSpace("refresh-store.flows");
	expect([...declared.guarantees].sort()).toEqual(
		["authenticated", "confirmed-reads", "durable", "no-eviction", "replicated"].sort(),
	);
	expect(declared.subjectData).toBe("retained");
	const app = await assemble({
		modules: [storeModule, transparencyStore, wiring],
		config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
		runtime: quietRuntime(),
	});
	const frames = await app.get(frameStore);
	expect(frames.parts).toContain(familiesPart);
	const unit = { flow: { of: "subject", id: "s1" } } as const;
	const records = [{ part: familiesPart, name: "state" }];
	const read = await frames.read(unit, records);
	const state = { families: {} };
	expect(await frames.write(read, { records: [{ value: state }] }, read.now + 1000)).toBe(
		"written",
	);
	expect((await frames.read(unit, records)).held).toEqual([state]);
});
