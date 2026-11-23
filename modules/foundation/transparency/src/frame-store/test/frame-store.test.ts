import { assemble, BuildRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { describe, expect, it } from "vitest";
import { frameStoreContract } from "../../testing.ts";
import { frameStoreOver } from "../frame-store.ts";

const guarantees = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	"authenticated",
] as const;
let opened = 0;
/** A memory store over a frames space and a part's space, fresh for each call. */
async function storeWith(partGuarantees: readonly Space["guarantees"][number][] = guarantees) {
	opened += 1;
	const frames: Space = {
		name: `frames${opened}`,
		guarantees: [...guarantees],
		subjectData: "retained",
	};
	const part: Space = {
		name: `part${opened}`,
		guarantees: [...partGuarantees],
		subjectData: "none",
	};
	const declaring = defineModule({ name: "declaring", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(spaces).by(() => frames),
		m.contribute(spaces).by(() => part),
	]);
	const app = await assemble({
		modules: [storeModule, declaring],
		config: { ...kernelConfig(), ...storeConfig({ "accept-unauthenticated": true }) },
		runtime: quietRuntime(),
	});
	return { s: await app.get(store), frames, part };
}
const refuse = (where: string, reason: string): never => {
	throw new BuildRefused(where, reason);
};
const { random } = quietRuntime();

frameStoreContract("frames over the memory store", {
	open: async () => {
		const { s, frames, part } = await storeWith();
		return {
			frames: frameStoreOver({
				store: s,
				space: frames,
				parts: [{ name: "p", space: part }],
				random,
				refuse,
			}),
			part: "p",
		};
	},
});

describe("frames over a store", () => {
	it("refuses a store that writes no records of two partitions as one", async () => {
		const { s, frames } = await storeWith();
		const { batchAcross: _none, ...lacking } = s;
		expect(() =>
			frameStoreOver({ store: lacking as Store, space: frames, parts: [], random, refuse }),
		).toThrow(/writes no records of two partitions as one/);
	});

	it("refuses a part whose space declares other guarantees than the frames'", async () => {
		const { s, frames, part } = await storeWith(["durable", "replicated"]);
		expect(() =>
			frameStoreOver({
				store: s,
				space: frames,
				parts: [{ name: "p", space: part }],
				random,
				refuse,
			}),
		).toThrow(/part p declares other guarantees/);
	});

	it("keeps the frame and the records with no expiry: a lease's end deletes nothing", async () => {
		const { s, frames, part } = await storeWith();
		const over = frameStoreOver({
			store: s,
			space: frames,
			parts: [{ name: "p", space: part }],
			random,
			refuse,
		});
		const unit = { flow: { of: "subject", id: "s1" } } as const;
		const read = await over.read(unit, [{ part: "p", name: "a" }]);
		await over.write(read, { frame: { applied: 1 }, records: [{ value: 1 }] }, read.now + 1000);
		const frameEntry = await s.get({ space: frames, partition: "subject:s1", name: "frame" });
		const record = await s.get({ space: part, partition: "subject:s1", name: "a" });
		expect([frameEntry.entry?.expiresAt, record.entry?.expiresAt]).toEqual([null, null]);
	});

	it("refuses a record of a part it does not bind", async () => {
		const { s, frames } = await storeWith();
		const over = frameStoreOver({ store: s, space: frames, parts: [], random, refuse });
		await expect(
			over.read({ flow: { of: "subject", id: "s1" } }, [{ part: "x", name: "a" }]),
		).rejects.toThrow(TypeError);
	});
});
