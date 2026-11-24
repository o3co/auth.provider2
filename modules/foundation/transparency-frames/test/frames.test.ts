import { assemble, BuildRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Guarantee, type Space, type Store, spaces, store } from "@mod/store";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { frameStoreContract } from "@mod/transparency/testing";
import { describe, expect, it } from "vitest";
import { frameStoreOver } from "../src/frames.ts";

const all: readonly Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	"authenticated",
];
let opened = 0;
/** A memory store over a frames space and a part's space, fresh for each call. */
async function storeWith(part: Partial<Space> = {}) {
	opened += 1;
	const frames: Space = { name: `frames${opened}`, guarantees: [...all], subjectData: "retained" };
	const partSpace: Space = {
		name: `part${opened}`,
		guarantees: [...all],
		subjectData: "none",
		...part,
	};
	const declaring = defineModule({ name: "declaring", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(spaces).by(() => frames),
		m.contribute(spaces).by(() => partSpace),
	]);
	const app = await assemble({
		modules: [storeModule, declaring],
		config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
		runtime: quietRuntime(),
	});
	return { s: await app.get(store), frames, part: partSpace };
}
const refuse = (where: string, reason: string): never => {
	throw new BuildRefused(where, reason);
};
const { random } = quietRuntime();
const over = (s: Store, frames: Space, parts: readonly { name: string; space: Space }[]) =>
	frameStoreOver({ store: s, space: frames, parts, random, where: "the-wiring", refuse });

frameStoreContract("transparency-frames over the memory store", {
	open: async () => {
		const { s, frames, part } = await storeWith();
		return { frames: over(s, frames, [{ name: "p", space: part }]), part: "p" };
	},
});

describe("frames over records", () => {
	it("lists the client flows holding a record by a scan of the frames' space, none of a subject's frame or a part's record", async () => {
		const { s, frames, part } = await storeWith();
		const store = over(s, frames, [{ name: "p", space: part }]);
		const client = { flow: { of: "client", id: "c1" }, op: "o1" } as const;
		const read = await store.read(client, [{ part: "p", name: "r" }]);
		await store.write(
			read,
			{ frame: { applied: 0 }, flow: ["o1"], records: [{ value: 1 }] },
			read.now + 10_000,
		);
		const subject = await store.read({ flow: { of: "subject", id: "c2" } }, []);
		await store.write(subject, { frame: { applied: 0 }, records: [] }, subject.now + 10_000);
		expect(await store.clientFlows?.()).toEqual({ flows: [{ of: "client", id: "c1" }] });
	});

	it("refuses, naming its wiring, a store that writes no records of two partitions as one", async () => {
		const { s, frames } = await storeWith();
		const { batchAcross: _none, ...lacking } = s;
		expect(() => over(lacking as Store, frames, [])).toThrow(
			/writes no records of two partitions as one/,
		);
	});

	it("refuses a part whose space declares other guarantees than the frames'", async () => {
		const { s, frames, part } = await storeWith({ guarantees: ["durable", "replicated"] });
		expect(() => over(s, frames, [{ name: "p", space: part }])).toThrow(
			/declares other guarantees than frames/,
		);
	});

	it("refuses a part whose space holds a subject's data: a Step writes none of subject-records' spaces", async () => {
		for (const subjectData of ["online-indexed", "online-keyed", "bounded", "internal"] as const) {
			const { s, frames, part } = await storeWith({ subjectData });
			expect(() => over(s, frames, [{ name: "p", space: part }]), subjectData).toThrow(
				/holds a subject's data, or an index of one/,
			);
		}
	});

	it("keeps the frame and the records with no expiry: a lease's end deletes nothing", async () => {
		const { s, frames, part } = await storeWith();
		const built = over(s, frames, [{ name: "p", space: part }]);
		const unit = { flow: { of: "subject", id: "s1" } } as const;
		const read = await built.read(unit, [{ part: "p", name: "a" }]);
		await built.write(read, { frame: { applied: 1 }, records: [{ value: 1 }] }, read.now + 1000);
		const pages = await Promise.all([s.scan(frames), s.scan(part)]);
		const keys = pages.flatMap((page) => page.keys);
		const entries = await Promise.all(keys.map((key) => s.get(key)));
		expect(entries.map((e) => e.entry?.expiresAt)).toEqual([null, null]);
	});

	it("refuses a record of a part it does not bind", async () => {
		const { s, frames } = await storeWith();
		const unit = { flow: { of: "subject", id: "s1" } } as const;
		await expect(over(s, frames, []).read(unit, [{ part: "x", name: "a" }])).rejects.toThrow(
			TypeError,
		);
	});
});

describe("a client's flow's record", () => {
	const op = (name: string) => ({ flow: { of: "client", id: "c1" }, op: name }) as const;

	it("is read with each op's frame and written in its write, held to it; read alone too", async () => {
		const { s, frames, part } = await storeWith();
		const store = over(s, frames, [{ name: "p", space: part }]);
		const a = await store.read(op("a"), []);
		expect(a.flow).toBeUndefined();
		expect(await store.write(a, { frame: { x: 1 }, flow: ["a"], records: [] }, a.now + 1000)).toBe(
			"written",
		);
		const b = await store.read(op("b"), []);
		expect([b.frame, b.flow]).toEqual([undefined, ["a"]]);
		// Another op's write of the same flow's record moves it.
		const again = await store.read(op("a"), []);
		expect(
			await store.write(b, { frame: { x: 2 }, flow: ["a", "b"], records: [] }, b.now + 1000),
		).toBe("written");
		expect(await store.write(again, { drop: true, flow: [], records: [] }, again.now + 1000)).toBe(
			"moved",
		);
		expect(await store.flowRecord?.({ of: "client", id: "c1" })).toEqual(["a", "b"]);
		const fresh = await store.read(op("a"), []);
		expect(
			await store.write(fresh, { drop: true, flow: ["b"], records: [] }, fresh.now + 1000),
		).toBe("written");
		expect((await store.read(op("a"), [])).frame).toBeUndefined();
		expect(await store.flowRecord?.({ of: "client", id: "c1" })).toEqual(["b"]);
	});
});
