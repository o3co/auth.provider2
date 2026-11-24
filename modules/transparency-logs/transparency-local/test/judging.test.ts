import type { Stage } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import {
	approval,
	boot,
	firstKey,
	passkey,
	subjectFlow,
	testClock,
	type World,
} from "./fixtures/world.ts";

/** Appends a stage at the flow's head and reads back the finding it was placed with. */
async function placed(world: World, stage: Stage) {
	const answer = await world.log.append(stage, await world.log.head(stage.flow));
	if (answer.result !== "accepted") throw new Error(`refused: ${answer.refusal}`);
	return world.log.at(stage.flow, answer.position);
}

describe("transparency-local's judgment (j0)", () => {
	it("judges a first key at once, its ring's statements and the key's assertion verified: unsupported, took", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = subjectFlow();
		const stage = await firstKey(world, flow, await passkey(), { now: clock.now() });
		const at = await placed(world, stage);
		expect(at?.finding).toEqual({ verdict: "unsupported", outcome: "took" });
		expect(at?.changes).toBeUndefined();
	});

	it("judges forged a first key whose possession another key asserts", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = subjectFlow();
		const key = await passkey();
		const stage = await firstKey(world, flow, key, { now: clock.now() });
		const other = await passkey();
		const evidence = stage.preimage.evidence.map((e) =>
			e.form === "assertion"
				? { ...e, value: other.asserts(stage.preimage.evidence[1]?.value ?? "") }
				: e,
		);
		const forged = { ...stage, preimage: { ...stage.preimage, evidence } };
		expect((await placed(world, forged))?.finding).toEqual({
			verdict: "forged",
			outcome: "didNotTake",
		});
	});

	it("judges an assertion for the origin its section names, of those webauthn lists", async () => {
		const clock = testClock();
		const world = await boot({ clock, section: { origin: "https://elsewhere.example" } });
		const stage = await firstKey(world, subjectFlow(), await passkey(), { now: clock.now() });
		expect((await placed(world, stage))?.finding?.verdict).toBe("forged");
	});

	it("judges a stage on time by its acceptance time, the kernel's clock", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const stage = await firstKey(world, subjectFlow(), await passkey(), { now: clock.now() });
		clock.move(10 * 60_000);
		expect((await placed(world, stage))?.finding).toEqual({
			verdict: "unsupported",
			outcome: "didNotTake",
		});
	});

	it("judges each record on its flow's judged prefix: an approval by the key placed before it", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = subjectFlow();
		const key = await passkey();
		const first = await placed(world, await firstKey(world, flow, key, { now: clock.now() }));
		world.held.hold(key.credential, flow.id);
		const parent = first?.record.id ?? "";
		const by = await approval(world, flow, key, { now: clock.now(), parent });
		expect((await placed(world, by))?.finding).toEqual({ verdict: "unsupported", outcome: "took" });
		const none = await approval(world, flow, key, { now: clock.now(), parent: "unknown" });
		expect((await placed(world, none))?.finding?.verdict).toBe("forged");
	});

	it("judges forged a record whose root key's credential passkeys holds no key of, or holds for another subject", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = subjectFlow();
		const key = await passkey();
		const first = await placed(world, await firstKey(world, flow, key, { now: clock.now() }));
		const parent = first?.record.id ?? "";
		const unheld = await approval(world, flow, key, { now: clock.now(), parent });
		expect((await placed(world, unheld))?.finding).toEqual({
			verdict: "forged",
			outcome: "didNotTake",
		});
		world.held.hold(key.credential, "someone-else");
		const elsewhere = await approval(world, flow, key, { now: clock.now(), parent });
		expect((await placed(world, elsewhere))?.finding?.verdict).toBe("forged");
	});

	it("judges forged a client's start and bundle, as the rules hold no op of a client's flow yet (KG-07)", async () => {
		const world = await boot();
		const flow = { of: "client", id: "c1" } as const;
		const start = await world.log.append({
			kind: "start",
			flow,
			op: "cc1",
			stage: 1,
			last: false,
			preimage: { v: 1, parent: "a1", evidence: [], content: { via: "code" } },
		});
		if (start.result !== "accepted") throw new Error(start.refusal);
		const bundle = await world.log.append({
			kind: "bundle",
			flow,
			op: "cc1",
			stage: 2,
			last: true,
			tokens: [{ frame: "accessToken", digest: "a".repeat(43) }],
			preimage: { v: 1, parent: start.id, root: "a1", evidence: [], content: { via: "code" } },
		});
		if (bundle.result !== "accepted") throw new Error(bundle.refusal);
		for (const position of [start.position, bundle.position]) {
			expect((await world.log.at(flow, position))?.finding?.verdict).toBe("forged");
		}
	});
});
