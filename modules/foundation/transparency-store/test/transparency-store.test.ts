import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Guarantee, type Space, type Store, spaces, store } from "@mod/store";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { frameStore } from "@mod/transparency";
import { frameStoreContract } from "@mod/transparency/testing";
import { frameParts } from "@mod/transparency-frames";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const all: Guarantee[] = [
	"no-eviction",
	"durable",
	"replicated",
	"confirmed-reads",
	"authenticated",
];
let parts = 0;
/** A part's owner's wiring: its space declared, and bound to the part. */
function partModule(
	guarantees: readonly Guarantee[] = all,
	subjectData: Space["subjectData"] = "none",
) {
	parts += 1;
	const space: Space = { name: `part${parts}`, guarantees: [...guarantees], subjectData };
	const module = defineModule({ name: `part${parts}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(spaces).by(() => space),
		m.contribute(frameParts).by(() => ({ name: "p", space })),
	]);
	return module;
}
const config = (settings = { "accept-unauthenticated": true }) => ({
	...kernelConfig(),
	...storeConfig(settings),
});
const refusal = (error: unknown) =>
	BootRefused.is(error)
		? error.refusals.map((r) => `${r.where}: ${r.reason}`).join("\n")
		: String(error);

frameStoreContract("transparency-store over the memory store", {
	open: async () => {
		const app = await assemble({
			modules: [storeModule, wiring, partModule()],
			config: config(),
			runtime: quietRuntime(),
		});
		return { frames: await app.get(frameStore), part: "p" };
	},
});

describe("transparency-store", () => {
	it("declares the frames' space with a guarantee for each need transparency states", async () => {
		const simulated = simulatedStore();
		await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		const declared = simulated.declaredSpace("transparency-store.frames");
		expect([...declared.guarantees].sort()).toEqual([...all].sort());
		expect(declared.subjectData).toBe("retained");
	});

	it("boots over a store that does not tell an outside write apart only as the store's setting accepts", async () => {
		const refused = await assemble({
			modules: [storeModule, wiring],
			config: config({ "accept-unauthenticated": false }),
			runtime: quietRuntime(),
		}).catch(refusal);
		expect(refused).toMatch(/store\.accept-unauthenticated: .*transparency-store\.frames/);
	});

	it("refuses to boot over a store that writes no records of two partitions as one", async () => {
		const lacking = defineModule({ name: "store", replicaSafe: true, takes: [spaces] }, (m) => [
			m.provide(store).by(async (c) => {
				await c.collect(spaces);
				return { get: async () => ({ entry: null, now: 0 }) } as unknown as Store;
			}),
		]);
		const refused = await assemble({
			modules: [lacking, wiring],
			config: kernelConfig(),
			runtime: quietRuntime(),
		})
			.then(() => "booted")
			.catch(refusal);
		expect(refused).toMatch(
			/transparency-store: its store writes no records of two partitions as one/,
		);
	});

	it("refuses to boot when a part's space declares other guarantees than the frames'", async () => {
		const refused = await assemble({
			modules: [storeModule, wiring, partModule(["durable", "replicated"])],
			config: config(),
			runtime: quietRuntime(),
		})
			.then(() => "booted")
			.catch(refusal);
		expect(refused).toMatch(
			/transparency-store: space part\d+ declares other guarantees than transparency-store\.frames/,
		);
	});

	it("refuses to boot when a part's space holds a subject's data, which a Step's write cannot reach", async () => {
		const refused = await assemble({
			modules: [storeModule, wiring, partModule(all, "online-indexed")],
			config: config(),
			runtime: quietRuntime(),
		})
			.then(() => "booted")
			.catch(refusal);
		expect(refused).toMatch(
			/transparency-store: space part\d+ holds a subject's data, or an index of one/,
		);
	});
});
