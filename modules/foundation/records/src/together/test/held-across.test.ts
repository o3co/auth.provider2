import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { describe, expect, it } from "vitest";
import { type Place, recordsHeldAcross, recordsIn } from "../../records.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const guarantees = ["no-eviction", "durable", "replicated"] as const;
const frames: Space = { name: "held-frames", guarantees: [...guarantees], subjectData: "retained" };
const parts: Space = { name: "held-parts", guarantees: [...guarantees], subjectData: "none" };
const opened = contract<Store>("test.store");
const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};

/** A simulated store over two spaces of one guarantee, a place in each, held together. */
async function open() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", replicaSafe: true, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => frames),
				m.contribute(spaces).by(() => parts),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const s = app.get(opened);
	const framePlace: Place = { store: s, space: frames, random };
	const partPlace: Place = { store: s, space: parts, random };
	const held = recordsHeldAcross([framePlace, partPlace], "w", refuse);
	const at = { frame: { place: framePlace, key: "f1" }, part: { place: partPlace, key: "f1/a" } };
	return { simulated, s, held, at, framePlace, partPlace };
}

describe("records held across: read, then written once held to all read", () => {
	it("writes the records as one, endless, and reads them back with the store clock's time", async () => {
		const { s, held, at, framePlace } = await open();
		const read = await held.read([at.frame, at.part]);
		expect(read.values).toEqual([undefined, undefined]);
		expect(typeof read.now).toBe("number");
		const next = [{ value: { applied: 1 }, lifetimeMs: "endless" as const }, { value: 2 }];
		expect(await held.write(read, next, read.now + 1000)).toBe("written");
		expect((await held.read([at.frame, at.part])).values).toEqual([{ applied: 1 }, 2]);
		expect(await recordsIn(framePlace).read("f1")).toEqual({ applied: 1 });
		const { entry } = await s.get({ space: frames, partition: "f1", name: "record" });
		expect(entry?.expiresAt).toBeNull();
	});

	it("writes nothing once any record read has moved, a kept one too, and tries nothing again", async () => {
		const { simulated, held, at } = await open();
		const first = await held.read([at.frame, at.part]);
		await held.write(first, [{ value: 1, lifetimeMs: "endless" }, undefined], first.now + 1000);
		const stale = await held.read([at.frame, at.part]);
		let sends = 0;
		simulated.beforeNext("batchAcross", frames.name, async () => {
			sends += 1;
			const fresh = await held.read([at.frame, at.part]);
			await held.write(fresh, [undefined, { value: "other" }], fresh.now + 1000);
		});
		const next = [{ value: 2 }, undefined];
		expect(await held.write(stale, next, stale.now + 1000)).toBe("moved");
		expect(sends).toBe(1);
		expect((await held.read([at.frame, at.part])).values).toEqual([1, "other"]);
	});

	it("holds a write of nothing to what it read: written where nothing moved, moved where a record did", async () => {
		const { held, at } = await open();
		const read = await held.read([at.frame, at.part]);
		expect(await held.write(read, [undefined, undefined], read.now + 1000)).toBe("written");
		const stale = await held.read([at.frame, at.part]);
		const fresh = await held.read([at.frame, at.part]);
		await held.write(fresh, [undefined, { value: 1 }], fresh.now + 1000);
		expect(await held.write(stale, [undefined, undefined], stale.now + 1000)).toBe("moved");
	});

	it("removes a record, keeping the one given none", async () => {
		const { held, at } = await open();
		const first = await held.read([at.frame, at.part]);
		await held.write(first, [{ value: 1 }, { value: 2 }], first.now + 1000);
		const second = await held.read([at.frame, at.part]);
		expect(await held.write(second, [undefined, { remove: true }], second.now + 1000)).toBe(
			"written",
		);
		expect((await held.read([at.frame, at.part])).values).toEqual([1, undefined]);
	});

	it("refuses a write past the caller's deadline on the store clock, writing nothing", async () => {
		const { held, at } = await open();
		const read = await held.read([at.frame, at.part]);
		expect(await held.write(read, [{ value: 1 }, undefined], read.now - 1)).toBe("late");
		expect((await held.read([at.frame])).values).toEqual([undefined]);
	});

	it("resends a write whose answer was lost under its mark: it takes effect once", async () => {
		const { simulated, held, at } = await open();
		const read = await held.read([at.frame, at.part]);
		simulated.loseNextReply();
		expect(await held.write(read, [{ value: 1 }, { value: 2 }], read.now + 1000)).toBe("written");
		expect((await held.read([at.frame, at.part])).values).toEqual([1, 2]);
	});

	it("is a TypeError for a record of a place not held, one named twice, or another count written than read", async () => {
		const { s, held, at } = await open();
		const stray: Place = { store: s, space: { ...parts, name: "held-stray" }, random };
		await expect(held.read([{ place: stray, key: "x" }])).rejects.toThrow(TypeError);
		await expect(held.read([at.part, at.part])).rejects.toThrow(TypeError);
		await expect(held.read([])).rejects.toThrow(TypeError);
		const read = await held.read([at.frame]);
		await expect(held.write(read, [], read.now + 1000)).rejects.toThrow(TypeError);
	});
});

describe("records held across: what refuses the boot, through the builder's refuse", () => {
	const places = async () => {
		const { s, framePlace, partPlace } = await open();
		return { s, framePlace, partPlace };
	};

	it("refuses a store that writes no records of two partitions as one", async () => {
		const { s, framePlace } = await places();
		const { batchAcross: _none, ...lacking } = s;
		const place = { ...framePlace, store: lacking as Store };
		expect(() => recordsHeldAcross([place], "w", refuse)).toThrow(
			/w: its store writes no records of two partitions as one/,
		);
	});

	it("refuses places on two stores, or of spaces of other guarantees", async () => {
		const one = await places();
		const two = await places();
		expect(() => recordsHeldAcross([one.framePlace, two.partPlace], "w", refuse)).toThrow(
			/w: its places are on two stores/,
		);
		const weaker = { ...one.partPlace, space: { ...parts, guarantees: ["durable" as const] } };
		expect(() => recordsHeldAcross([one.framePlace, weaker], "w", refuse)).toThrow(
			/w: space held-parts declares other guarantees than held-frames/,
		);
	});

	it("refuses a space holding a subject's data, or an index of one, which subject-records writes", async () => {
		const { framePlace, partPlace } = await places();
		for (const subjectData of ["online-indexed", "online-keyed", "bounded", "internal"] as const) {
			const place = { ...partPlace, space: { ...parts, name: `held-${subjectData}`, subjectData } };
			expect(() => recordsHeldAcross([framePlace, place], "w", refuse), subjectData).toThrow(
				new RegExp(`w: space held-${subjectData} holds a subject's data, or an index of one`),
			);
		}
	});
});
