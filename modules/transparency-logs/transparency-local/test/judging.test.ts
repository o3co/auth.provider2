import type { Stage } from "@mod/transparency";
import { describe, expect, it } from "vitest";
import {
	approval,
	boot,
	clientBundle,
	clientEvidence,
	clientKey,
	clientStart,
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

	it.each(["EdDSA", "RS256"] as const)(
		"judges a first key of %s by its COSE_Key and thumbprint as it judges ES256's",
		async (algorithm) => {
			const clock = testClock();
			const world = await boot({ clock });
			const stage = await firstKey(world, subjectFlow(), await passkey(algorithm), {
				now: clock.now(),
			});
			expect((await placed(world, stage))?.finding).toEqual({
				verdict: "unsupported",
				outcome: "took",
			});
		},
	);

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

	it("judges a client's start and bundle verified: its evidence by a key its registry version writes, its token within its own ceiling", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = { of: "client", id: "svc" } as const;
		const key = clientKey();
		world.clients.hold({
			id: flow.id,
			version: 3,
			keys: [key.jwk],
			self: [{ audience: "https://api.example", scopes: ["read"] }],
		});
		const start = clientStart(flow, clientEvidence(flow.id, key, clock.now()), 3);
		const started = await world.log.append(start);
		if (started.result !== "accepted") throw new Error(started.refusal);
		expect((await world.log.at(flow, started.position))?.finding).toEqual({
			verdict: "verified",
			outcome: "took",
		});
		const bundle = await world.log.append(clientBundle(start, started, key));
		if (bundle.result !== "accepted") throw new Error(bundle.refusal);
		expect((await world.log.at(flow, bundle.position))?.finding?.verdict).toBe("verified");
		// Outside its own ceiling: forged.
		const other = clientStart(flow, clientEvidence(flow.id, key, clock.now()), 3);
		const second = await world.log.append(other);
		if (second.result !== "accepted") throw new Error(second.refusal);
		const wide = await world.log.append(clientBundle(other, second, key, { scope: "admin" }));
		if (wide.result !== "accepted") throw new Error(wide.refusal);
		expect((await world.log.at(flow, wide.position))?.finding?.verdict).toBe("forged");
	});

	it("takes a client's start whose evidence the Core took at the edge of its own windows, a request's time later", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = { of: "client", id: "svc" } as const;
		const key = clientKey();
		world.clients.hold({ id: flow.id, version: 3, keys: [key.jwk], self: [] });
		const evidence = clientEvidence(flow.id, key, clock.now());
		clock.move(5 * 60_000 + 10_000);
		const started = await world.log.append(clientStart(flow, evidence, 3));
		if (started.result !== "accepted") throw new Error(started.refusal);
		expect((await world.log.at(flow, started.position))?.finding).toEqual({
			verdict: "verified",
			outcome: "took",
		});
	});

	it("holds a client's start of a registry version the registry does not hold now, and forges one by another key", async () => {
		const clock = testClock();
		const world = await boot({ clock });
		const flow = { of: "client", id: "svc" } as const;
		const key = clientKey();
		world.clients.hold({ id: flow.id, version: 3, keys: [key.jwk], self: [] });
		const elsewhere = await world.log.append(
			clientStart(flow, clientEvidence(flow.id, key, clock.now()), 2),
		);
		if (elsewhere.result !== "accepted") throw new Error(elsewhere.refusal);
		expect((await world.log.at(flow, elsewhere.position))?.finding?.verdict).toBe("held");
		const forged = await world.log.append(
			clientStart(flow, clientEvidence(flow.id, clientKey(key.kid), clock.now()), 3),
		);
		if (forged.result !== "accepted") throw new Error(forged.refusal);
		expect((await world.log.at(flow, forged.position))?.finding?.verdict).toBe("forged");
	});

	it("judges forged a code's start and bundle on a client's flow", async () => {
		const world = await boot();
		const flow = { of: "client", id: "c1" } as const;
		const start = await world.log.append({
			kind: "start",
			flow,
			op: "cc1",
			stage: 1,
			last: false,
			elements: ["e".repeat(43)],
			// A code's start as V24 names it, its code and client: forged for its flow, not its shape.
			preimage: {
				v: 1,
				parent: "a1",
				evidence: [],
				content: { via: "code", code: "c".repeat(43), client: "c1" },
			},
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
