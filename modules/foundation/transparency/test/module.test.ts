import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import {
	frameStore,
	type OperationKind,
	operationKinds,
	type StateOwner,
	stateOwners,
	transparency,
	transparencyLog,
} from "../src/contract.ts";
import transparencyModule from "../src/module.ts";
import { memoryFrames } from "./fixtures/frames.ts";
import { logBook } from "./fixtures/log.ts";
import { allParts, issue, keyChange, owners } from "./fixtures/registrations.ts";

const flow = { of: "subject", id: "s1" } as const;

async function boot(
	p: {
		owners?: readonly StateOwner[];
		kinds?: readonly OperationKind[];
		parts?: readonly string[];
		section?: Record<string, unknown>;
	} = {},
) {
	const frames = memoryFrames(p.parts ?? allParts);
	const book = logBook(frames.clock.now);
	const fakes = defineModule({ name: "fakes", replicaSafe: true, takes: [] }, (m) => [
		m.provide(frameStore).by(() => frames.frames),
		m.provide(transparencyLog).by(() => book.as("w1")),
	]);
	const registering = defineModule({ name: "registering", replicaSafe: true, takes: [] }, (m) => [
		...(p.owners ?? owners).map((owner) => m.contribute(stateOwners).by(() => owner)),
		...(p.kinds ?? [issue, keyChange]).map((kind) => m.contribute(operationKinds).by(() => kind)),
	]);
	const app = await assemble({
		modules: [fakes, registering, transparencyModule],
		config: { ...kernelConfig(), ...(p.section ? { transparency: p.section } : {}) },
		runtime: quietRuntime(),
	});
	return { app, frames };
}
const refusals = async (p: Parameters<typeof boot>[0]) => {
	const refused = await boot(p).then(
		() => undefined,
		(error: unknown) => error,
	);
	if (!BootRefused.is(refused)) throw new Error("the boot was not refused");
	return (refused as BootRefused).refusals.map((r) => r.reason).join("\n");
};

describe("transparency's module", () => {
	it("provides the writers' contract over the frame store and the log, with its lease", async () => {
		const { app, frames } = await boot({ section: { lease: "2s" } });
		const t = await app.get(transparency);
		const decided = await t.decide({
			kind: "issue",
			flow,
			op: "op1",
			decide: () => ({ digest: "d", eff: {}, records: [] }),
		});
		expect(decided).toEqual({ prev: 0 });
		expect(frames.value(flow)).toMatchObject({ intent: { leaseEnd: 2000 } });
	});

	it("refuses to boot unless every field of a flow's state has one owner", async () => {
		expect(await refusals({ owners: owners.slice(1) })).toMatch(/keyGeneration.*no owner/s);
		const [first] = owners;
		if (!first) throw new Error("no owner");
		const twice = [...owners, { ...first, name: "again", parts: ["keys"] }];
		expect(await refusals({ owners: twice })).toMatch(/keys is held by keys and again/);
	});

	it("refuses to boot a registration naming a part no place is bound to", async () => {
		expect(await refusals({ parts: ["keys", "grants", "families"] })).toMatch(
			/key names part reservations, which no place is bound to/,
		);
	});
});
