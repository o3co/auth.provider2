import type { Finding } from "@mod/authority-rules";
import type { Json } from "@mod/store";
import { opIds } from "@mod/transparency-wire";
import { beforeEach, describe, expect, it } from "vitest";
import { memoryFrames } from "../../../test/fixtures/frames.ts";
import { logBook } from "../../../test/fixtures/log.ts";
import {
	allParts,
	issue,
	keyChange,
	keyStage,
	owners,
	type Reservation,
	reservationRecord,
	seeded,
} from "../../../test/fixtures/registrations.ts";
import type { Stage } from "../../contract.ts";
import { transparencyOver } from "../driver.ts";

const flow = { of: "subject", id: "s1" } as const;
const leaseMs = 5000;
const verified: Finding = { verdict: "verified", outcome: "took" };
const held: Finding = { verdict: "held", outcome: "took" };
const reservation: Reservation = {
	version: "res1",
	state: "verified",
	credential: "c2",
	publicKey: "p2",
};
const bundleEff = { family: { approval: "a1" }, consume: ["code:a1"] };
const bundleStage = (op: string): Stage => ({
	kind: "bundle",
	flow,
	op,
	stage: 1,
	last: true,
	tokens: [{ frame: "accessToken", digest: "A".repeat(43) }],
	preimage: { v: 1, evidence: [], content: { via: "code" } },
});

let world: ReturnType<typeof makeWorld>;
function makeWorld() {
	const store = memoryFrames(allParts);
	const log = logBook(store.clock.now);
	const replica = (instance: string) =>
		transparencyOver({
			frames: store.frames,
			log: log.as(instance),
			kinds: [issue, keyChange],
			owners,
			leaseMs,
		});
	for (const [part, value] of Object.entries(seeded)) {
		store.put(flow, { part, name: "state" }, value as unknown as Json);
	}
	store.put(flow, reservationRecord, reservation as unknown as Json);
	const frame = () =>
		store.value(flow) as { applied: number; intent: Record<string, unknown> | null };
	const part = (name: string) =>
		store.value(flow, { part: name, name: "state" }) as Record<string, Json>;
	const res = () => store.value(flow, reservationRecord) as unknown as Reservation;
	return { store, log, w1: replica("w1"), w2: replica("w2"), w3: replica("w3"), frame, part, res };
}
beforeEach(() => {
	world = makeWorld();
});

const decideIssue = (op = "op1") =>
	world.w1.decide({
		kind: "issue",
		flow,
		op,
		decide: () => ({ digest: "d1", eff: bundleEff, records: [] }),
	});
const decideKey = (who = world.w1) =>
	who.decide({
		kind: "key",
		flow,
		op: reservation.version,
		decide: (_state, [r]) =>
			(r as unknown as Reservation)?.state === "verified"
				? {
						digest: "dk",
						eff: { key: { credential: "c2", publicKey: "p2" } },
						records: [undefined],
					}
				: { refused: "notVerified" },
	});

describe("KE-C04: one Step is one write of the frame and every owner's records, the fold applied once", () => {
	it("takes the owner's bundle in: its family and its use-once mark land in their owners' records with the frame", async () => {
		expect(await decideIssue()).toEqual({ prev: 0 });
		const sent = await world.w1.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 });
		expect(sent).toMatchObject({ answer: { result: "accepted", position: 1 } });
		expect(await world.w1.step({ flow, own: "op1" })).toEqual({ refused: "unjudged" });
		world.log.judge(flow, 1, verified);
		expect(await world.w2.step({ flow })).toEqual({ refused: "waits" });
		expect(await world.w1.step({ flow, own: "op1" })).toEqual({
			position: 1,
			end: { op: "op1", kind: "issue", ending: "took", owner: true },
		});
		expect(world.frame()).toMatchObject({ applied: 1, intent: { state: "done", eff: null } });
		expect(Object.keys(world.part("families").families as object)).toEqual(["r1"]);
		expect(world.part("grants").consumed).toEqual(["code:a1"]);
	});

	it("takes a monitor's record on a flow with no intent by the same path: a denial revokes in every owner's records", async () => {
		world.log.monitor(flow, "denial", { revoke: "k1" });
		expect(await world.w2.step({ flow })).toEqual({ position: 1 });
		expect(world.frame()).toEqual({ applied: 1, generation: 1, intent: null });
		expect(world.part("keys").keys).toEqual({});
		expect(world.part("grants").approvals).toEqual({});
	});

	it("moves the key generation on at an erasure boundary, keeping the use-once marks", async () => {
		world.store.put(flow, { part: "grants", name: "state" }, {
			...seeded.grants,
			consumed: ["code:a0"],
		} as unknown as Json);
		world.log.monitor(flow, "erasureBoundary", {});
		await world.w3.step({ flow });
		expect(world.part("keys")).toEqual({ keyGeneration: 1, keys: {} });
		expect(world.part("grants")).toEqual({ approvals: {}, consumed: ["code:a0"] });
	});

	it("writes nothing when another writer moved any record it read: the CAS loser goes idle", async () => {
		world.log.monitor(flow, "denial", { revoke: "k1" });
		world.store.beforeWrite(() =>
			world.store.put(flow, { part: "families", name: "state" }, { families: {} }),
		);
		expect(await world.w2.step({ flow })).toEqual({ refused: "moved" });
		expect(world.frame()).toBeUndefined();
		expect(Object.keys(world.part("keys").keys as object)).toEqual(["k1"]);
	});

	it("refuses an owner's write that would commit past its lease: an old lease writes nothing", async () => {
		await decideIssue();
		await world.w1.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 });
		world.log.judge(flow, 1, verified);
		world.store.beforeWrite(() => world.store.clock.set(leaseMs));
		expect(await world.w1.step({ flow, own: "op1" })).toEqual({ refused: "late" });
		expect(world.frame()).toMatchObject({ applied: 0, intent: { state: "pending" } });
		expect(world.part("families").families).toEqual({});
	});

	it("ends an op with its own kind's records, though that op's intent landed between the Step's reads", async () => {
		world.log.monitor(flow, "confirmation", {});
		await world.w3.step({ flow });
		const read = world.store.frames.read.bind(world.store.frames);
		let reads = 0;
		world.store.frames.read = async (f, records) => {
			reads += 1;
			// After the Step's read of the frame alone: a key change is decided, sent and judged.
			if (reads === 2) {
				await decideKey(world.w3);
				await world.w3.send({ flow, op: "res1", stage: keyStage(flow, reservation), prev: 1 });
				world.log.judge(flow, 2, verified);
			}
			return read(f, records);
		};
		expect(await world.w3.step({ flow, own: "res1" })).toMatchObject({ end: { ending: "took" } });
		world.store.frames.read = read;
		expect(world.res().state).toBe("active");
	});

	it("takes in nothing past the head", async () => {
		expect(await world.w1.step({ flow })).toEqual({ refused: "atHead" });
	});
});

describe("the key change's reservation is the writer's record, held to the frame in each write (c)", () => {
	it("decides the op in one write held to the reservation: a cancel landing first moves it", async () => {
		world.store.beforeWrite(() =>
			world.store.put(flow, reservationRecord, {
				...reservation,
				state: "cancelled",
			} as unknown as Json),
		);
		expect(await decideKey()).toEqual({ refused: "moved" });
		expect(world.frame()).toBeUndefined();
		expect(await decideKey()).toEqual({ refused: "notVerified" });
	});

	it("refuses the reservation's cancel, retry or sweep while its op is being appended, the frame alone showing it", async () => {
		expect(await decideKey()).toEqual({ prev: 0 });
		const cancel = (r: readonly (Json | undefined)[]) => [
			{ value: { ...(r[0] as object), state: "cancelled" } as Json },
		];
		expect(
			await world.w2.changeHeld({ flow, records: [reservationRecord], change: cancel }),
		).toEqual({ refused: "open" });
		expect(world.res().state).toBe("verified");
	});

	it("confirms the reservation in the write that takes the key in; the two never part", async () => {
		await decideKey();
		await world.w1.send({ flow, op: "res1", stage: keyStage(flow, reservation), prev: 0 });
		world.log.judge(flow, 1, verified);
		expect(await world.w1.step({ flow, own: "res1" })).toMatchObject({
			end: { ending: "took", owner: true },
		});
		expect(world.res().state).toBe("active");
		expect(Object.keys(world.part("keys").keys as object).sort()).toEqual(["k1", "r1"]);
		expect(
			await world.w2.changeHeld({
				flow,
				records: [reservationRecord],
				change: () => [{ value: { ...reservation, version: "res2" } as unknown as Json }],
			}),
		).toEqual({ changed: true });
	});

	it("releases a held key record's reservation, ending its version, in the Step's write", async () => {
		await decideKey();
		await world.w1.send({ flow, op: "res1", stage: keyStage(flow, reservation), prev: 0 });
		world.log.judge(flow, 1, held);
		await world.w1.step({ flow, own: "res1" });
		expect(world.res().state).toBe("ended");
		expect(world.frame()).toMatchObject({ intent: { state: "closed", lastTaken: true } });
	});

	it("closes the op without a record on its first stage's prevMismatch, releasing the version to decide again", async () => {
		await decideKey();
		world.log.monitor(flow, "confirmation", {});
		const sent = await world.w1.send({
			flow,
			op: "res1",
			stage: keyStage(flow, reservation),
			prev: 0,
		});
		expect(sent).toMatchObject({
			answer: { result: "refused", refusal: "prevMismatch" },
			end: { ending: "refused", owner: true },
		});
		expect(world.frame()).toMatchObject({ intent: { state: "closed", lastTaken: false } });
		expect(world.res().state).toBe("verified");
	});
});

describe("orphans: the Mark, the takeover and the abandonment record", () => {
	it("lets one claim through when two replicas claim one orphan (OneClaim, ClaimExclusive)", async () => {
		await decideKey();
		world.store.clock.set(leaseMs);
		world.store.beforeWrite(async () => {
			expect(await world.w3.tend(flow)).toMatchObject({ did: "tookOver" });
		});
		expect(await world.w2.tend(flow)).toEqual({ stepped: 0 });
		expect(world.frame()).toMatchObject({ intent: { state: "pending", by: "w3", taken: true } });
	});

	it("lets a taker resend the op's stage from its reservation, then end it in its own tending", async () => {
		await decideKey();
		world.store.clock.set(leaseMs);
		const took = await world.w2.tend(flow);
		expect(took).toMatchObject({ did: "tookOver", answer: { result: "accepted", position: 1 } });
		expect(world.log.sent.at(-1)).toMatchObject({ instance: "w2", prev: 0, stage: { op: "res1" } });
		world.log.judge(flow, 1, verified);
		expect(await world.w3.step({ flow })).toEqual({ refused: "waits" });
		expect(await world.w2.tend(flow)).toEqual({ stepped: 1 });
		expect(world.res().state).toBe("active");
	});

	it("marks a bundle left alone abandoning, then any replica sends its abandonment after the head the same read showed", async () => {
		await decideIssue();
		await world.w1.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 });
		world.log.judge(flow, 1, verified);
		world.store.clock.set(leaseMs);
		const first = await world.w2.tend(flow);
		expect(first).toMatchObject({ stepped: 1, did: "abandonment" });
		expect(world.frame()).toMatchObject({
			intent: { state: "abandoning", by: "w2", family: "r1" },
		});
		expect(world.log.sent.at(-1)).toMatchObject({
			instance: "w2",
			prev: 1,
			stage: {
				kind: "abandonment",
				op: opIds.abandonment("op1", 1),
				abandons: { op: "op1", attempt: 1, digest: "d1" },
			},
		});
		world.log.judge(flow, 2, verified);
		expect(await world.w3.tend(flow)).toEqual({ stepped: 1 });
		expect(world.frame()).toMatchObject({ applied: 2, intent: { state: "closed" } });
		expect(world.part("families").families).toEqual({});
	});

	it("sends the empty abandonment of an orphan with no record only once it is marked", async () => {
		await decideIssue();
		world.store.clock.set(leaseMs);
		expect(await world.w2.tend(flow)).toEqual({ stepped: 0, did: "marked" });
		expect(world.log.sent).toEqual([]);
		const sent = await world.w3.tend(flow);
		expect(sent).toMatchObject({ did: "abandonment", answer: { result: "accepted" } });
		expect(world.log.sent.at(-1)).toMatchObject({ instance: "w3", prev: 0 });
	});

	it("sends the next attempt with a new id after a held abandonment", async () => {
		await decideIssue();
		world.store.clock.set(leaseMs);
		await world.w2.tend(flow);
		await world.w2.tend(flow);
		world.log.judge(flow, 1, held);
		expect(await world.w3.tend(flow)).toMatchObject({ stepped: 1, did: "abandonment" });
		expect(world.log.sent.at(-1)?.stage.op).toBe(opIds.abandonment("op1", 2));
	});

	it("puts one record on the log when two replicas send the same abandonment, both then idle", async () => {
		await decideIssue();
		world.store.clock.set(leaseMs);
		await world.w2.tend(flow);
		const [a, b] = await Promise.all([world.w2.tend(flow), world.w3.tend(flow)]);
		expect([a.answer?.result, b.answer?.result]).toEqual(["accepted", "accepted"]);
		expect(world.log.records(flow)).toHaveLength(1);
		expect(world.frame()).toMatchObject({ intent: { state: "abandoning" } });
	});

	it("refuses a send by a replica that is not the live owner", async () => {
		await decideIssue();
		expect(await world.w2.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 })).toEqual({
			refused: "notOwner",
		});
		world.store.clock.set(leaseMs);
		expect(await world.w1.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 })).toEqual({
			refused: "notOwner",
		});
	});
});

describe("the owner's next stage after a record landed between its stages", () => {
	const { tokens: _none, ...bundled } = bundleStage("op1");
	const startStage: Stage = { ...bundled, kind: "start", last: false };
	const later: Stage = { ...bundleStage("op1"), stage: 2 };

	async function landedBetween() {
		await decideIssue();
		await world.w1.send({ flow, op: "op1", stage: startStage, prev: 0 });
		world.log.judge(flow, 1, verified);
		world.log.monitor(flow, "confirmation", {});
		expect(await world.w1.send({ flow, op: "op1", stage: later, prev: 1 })).toMatchObject({
			answer: { refusal: "prevMismatch" },
		});
		expect(await world.w1.rebase({ flow, op: "op1", recheck: () => true })).toEqual({
			refused: "notReady",
		});
		await world.w1.step({ flow });
		await world.w1.step({ flow });
	}

	it("moves its previous position to the head once the re-check passes there", async () => {
		await landedBetween();
		expect(await world.w1.rebase({ flow, op: "op1", recheck: () => true })).toEqual({ prev: 2 });
		expect(await world.w1.send({ flow, op: "op1", stage: later, prev: 2 })).toMatchObject({
			answer: { result: "accepted", position: 3 },
		});
	});

	it("closes the op without a record when the re-check fails", async () => {
		await landedBetween();
		expect(await world.w1.rebase({ flow, op: "op1", recheck: () => false })).toEqual({
			end: { op: "op1", kind: "issue", ending: "refused", owner: true },
		});
		expect(world.frame()).toMatchObject({ intent: { state: "closed" } });
	});
});
