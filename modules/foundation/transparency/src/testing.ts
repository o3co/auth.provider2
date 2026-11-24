import { describe, expect, it } from "vitest";
import type { FrameStore, IntentUnit, Json } from "./contract.ts";

export { memoryFrames } from "./memory-frames.ts";
export { logBook } from "./memory-log.ts";

/** What an implementation of the frame's store interface gives its contract test. */
export interface FrameStoreHarness {
	/** A frame store over fresh, empty places, with one part bound. */
	open(): Promise<{ readonly frames: FrameStore; readonly part: string }>;
}

/** The contract of the frame's store interface, run against any implementation. */
export function frameStoreContract(name: string, harness: FrameStoreHarness): void {
	const flow: IntentUnit = { flow: { of: "subject", id: "s1" } };
	const other: IntentUnit = { flow: { of: "subject", id: "s2" } };
	const client = (op: string): IntentUnit => ({ flow: { of: "client", id: "c1" }, op });
	const frame = (applied: number): Json => ({ applied });
	describe(`frame store contract: ${name}`, () => {
		it("names the part it binds", async () => {
			const { frames, part } = await harness.open();
			expect(frames.parts).toContain(part);
		});

		it("reads a new flow as holding nothing", async () => {
			const { frames, part } = await harness.open();
			const read = await frames.read(flow, [{ part, name: "r" }]);
			expect(read).toMatchObject({ frame: undefined, held: [undefined] });
			expect(typeof read.now).toBe("number");
		});

		it("writes the frame and the records as one, and reads them back", async () => {
			const { frames, part } = await harness.open();
			const records = [{ part, name: "a" }];
			const read = await frames.read(flow, records);
			const next = { frame: frame(1), records: [{ value: { a: 1 } }] };
			expect(await frames.write(read, next, read.now + 10_000)).toBe("written");
			expect(await frames.read(flow, records)).toMatchObject({ frame: frame(1), held: [{ a: 1 }] });
			expect((await frames.read(other, records)).frame).toBeUndefined();
		});

		it("writes nothing once any record read has moved, the ones it keeps too", async () => {
			const { frames, part } = await harness.open();
			const records = [
				{ part, name: "a" },
				{ part, name: "b" },
			];
			const stale = await frames.read(flow, records);
			const fresh = await frames.read(flow, records);
			await frames.write(fresh, { records: [undefined, { value: 2 }] }, fresh.now + 10_000);
			const next = { frame: frame(1), records: [{ value: 1 }, undefined] };
			expect(await frames.write(stale, next, stale.now + 10_000)).toBe("moved");
			expect(await frames.read(flow, records)).toMatchObject({
				frame: undefined,
				held: [undefined, 2],
			});
		});

		it("keeps a client's ops apart: each op is a unit of its own", async () => {
			const { frames, part } = await harness.open();
			const records = [{ part, name: "a" }];
			const read = await frames.read(client("o1"), records);
			await frames.write(read, { frame: frame(1), records: [{ value: 1 }] }, read.now + 10_000);
			expect(await frames.read(client("o2"), records)).toMatchObject({
				frame: undefined,
				held: [undefined],
			});
			expect((await frames.read(client("o1"), records)).frame).toEqual(frame(1));
		});

		it("holds a write of nothing to the read all the same", async () => {
			const { frames, part } = await harness.open();
			const records = [{ part, name: "a" }];
			const read = await frames.read(flow, records);
			expect(await frames.write(read, { records: [undefined] }, read.now + 10_000)).toBe("written");
			const stale = await frames.read(flow, records);
			const fresh = await frames.read(flow, records);
			await frames.write(fresh, { records: [{ value: 1 }] }, fresh.now + 10_000);
			expect(await frames.write(stale, { records: [undefined] }, stale.now + 10_000)).toBe("moved");
		});

		it("removes a record, keeping the frame where none is given", async () => {
			const { frames, part } = await harness.open();
			const records = [{ part, name: "a" }];
			const first = await frames.read(flow, records);
			await frames.write(first, { frame: frame(1), records: [{ value: 1 }] }, first.now + 10_000);
			const second = await frames.read(flow, records);
			expect(await frames.write(second, { records: [{ remove: true }] }, second.now + 10_000)).toBe(
				"written",
			);
			expect(await frames.read(flow, records)).toMatchObject({
				frame: frame(1),
				held: [undefined],
			});
		});

		it("refuses a write past its deadline on the store clock, writing nothing", async () => {
			const { frames, part } = await harness.open();
			const records = [{ part, name: "a" }];
			const read = await frames.read(flow, records);
			const next = { frame: frame(1), records: [{ value: 1 }] };
			expect(await frames.write(read, next, read.now - 1)).toBe("late");
			expect((await frames.read(flow, records)).frame).toBeUndefined();
		});

		it("keeps a client's flow's record with each of its ops' frames, held to their writes, and drops a frame", async () => {
			const { frames } = await harness.open();
			const c1 = { of: "client", id: "c1" } as const;
			const a = await frames.read(client("a"), []);
			expect(a.flow).toBeUndefined();
			expect(
				await frames.write(a, { frame: frame(1), flow: ["a"], records: [] }, a.now + 10_000),
			).toBe("written");
			const b = await frames.read(client("b"), []);
			expect(b.flow).toEqual(["a"]);
			const stale = await frames.read(client("a"), []);
			expect(
				await frames.write(b, { frame: frame(1), flow: ["a", "b"], records: [] }, b.now + 10_000),
			).toBe("written");
			expect(
				await frames.write(stale, { drop: true, flow: [], records: [] }, stale.now + 10_000),
			).toBe("moved");
			const fresh = await frames.read(client("a"), []);
			expect(
				await frames.write(fresh, { drop: true, flow: ["b"], records: [] }, fresh.now + 10_000),
			).toBe("written");
			expect((await frames.read(client("a"), [])).frame).toBeUndefined();
			expect(await frames.flowRecord(c1)).toEqual(["b"]);
			expect(await frames.flowRecord({ of: "client", id: "c2" })).toBeUndefined();
		});
	});
}
