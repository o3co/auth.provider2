import type { Finding } from "@mod/authority-rules";
import { isUnavailable } from "@mod/kernel";
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
import type { Json, Stage, TransparencyLog } from "../../contract.ts";
import { transparencyOver } from "../driver.ts";

const flow = { of: "subject", id: "s1" } as const;
const leaseMs = 5000;
const verified: Finding = { verdict: "verified", outcome: "took" };
const held: Finding = { verdict: "held", outcome: "took" };
const didNotTake: Finding = { verdict: "verified", outcome: "didNotTake" };
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
	const replica = (
		instance: string,
		p: { kinds?: (typeof keyChange)[]; log?: (l: TransparencyLog) => TransparencyLog } = {},
	) =>
		transparencyOver({
			frames: store.frames,
			log: (p.log ?? ((l) => l))(log.as(instance)),
			kinds: p.kinds ?? [issue, keyChange],
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
	return {
		store,
		log,
		replica,
		w1: replica("w1"),
		w2: replica("w2"),
		w3: replica("w3"),
		frame,
		part,
		res,
	};
}
beforeEach(() => {
	world = makeWorld();
});

const decideIssue = (op = "op1") =>
	world.w1.decide({
		kind: "issue",
		flow,
		op,
		decide: () => ({ digest: "d1".padEnd(43, "0"), eff: bundleEff, records: [] }),
	});
const decideKey = (who = world.w1) =>
	who.decide({
		kind: "key",
		flow,
		op: reservation.version,
		decide: (_state, [r]) =>
			(r as unknown as Reservation)?.state === "verified"
				? {
						digest: "dk".padEnd(43, "0"),
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
			await world.w2.changeHeld({
				kind: "key",
				flow,
				records: [reservationRecord],
				change: cancel,
			}),
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
				kind: "key",
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
		expect(world.frame()).toMatchObject({ intent: { state: "closed" } });
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
		expect(world.frame()).toMatchObject({ intent: { state: "closed" } });
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
				abandons: { op: "op1", attempt: 1, digest: "d1".padEnd(43, "0") },
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
		const both = await Promise.all([world.w2.tend(flow), world.w3.tend(flow)]);
		const accepted = { did: "abandonment", answer: { result: "accepted", position: 1 } };
		expect(both).toMatchObject([accepted, accepted]);
		expect(world.log.records(flow)).toHaveLength(1);
		// Every replica sends the same abandonment: its id, the op's digest, the empty preimage.
		const [first, second] = world.log.sent.map((sent) => sent.stage);
		expect(second).toEqual(first);
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

describe("the flow holds what an op did, though another op's intent came between (~InLogKey, Abn(o, ·))", () => {
	const decideKeyAgain = () => decideKey(world.w2);
	/** Another op, decided and taken in to its end between. */
	async function anotherOp(op: string) {
		const prev = world.log.records(flow).length;
		expect(await decideIssue(op)).toEqual({ prev });
		await world.w1.send({ flow, op, stage: bundleStage(op), prev });
		world.log.judge(flow, prev + 1, verified);
		expect(await world.w1.step({ flow, own: op })).toMatchObject({ end: { ending: "took" } });
	}

	it("never decides a key change again once its record is on the flow, held or not taken", async () => {
		for (const finding of [held, didNotTake]) {
			world = makeWorld();
			await decideKey();
			await world.w1.send({ flow, op: "res1", stage: keyStage(flow, reservation), prev: 0 });
			world.log.judge(flow, 1, finding);
			await world.w1.step({ flow, own: "res1" });
			await anotherOp("op2");
			expect(await decideKeyAgain()).toEqual({ refused: "ended" });
		}
	});

	it("never decides a bundle's op again once its bundle is on the flow, though held", async () => {
		await decideIssue("op1");
		await world.w1.send({ flow, op: "op1", stage: bundleStage("op1"), prev: 0 });
		world.log.judge(flow, 1, held);
		await world.w1.step({ flow, own: "op1" });
		await anotherOp("op2");
		expect(await decideIssue("op1")).toEqual({ refused: "ended" });
	});

	it("decides an op again after its empty abandonment, its next abandonment taking the next attempt", async () => {
		await decideIssue("op1");
		world.store.clock.set(leaseMs);
		await world.w2.tend(flow);
		await world.w2.tend(flow);
		world.log.judge(flow, 1, verified);
		await world.w3.tend(flow);
		expect(world.frame()).toMatchObject({ applied: 1, intent: { state: "closed" } });
		world.store.clock.set(0);
		await anotherOp("op2");
		expect(await decideIssue("op1")).toEqual({ prev: 2 });
		world.store.clock.set(leaseMs);
		await world.w2.tend(flow);
		expect(await world.w3.tend(flow)).toMatchObject({
			did: "abandonment",
			answer: { result: "accepted", position: 3 },
		});
		expect(world.log.sent.at(-1)?.stage.op).toBe(opIds.abandonment("op1", 2));
		world.log.judge(flow, 3, verified);
		await world.w2.tend(flow);
		expect(world.frame()).toMatchObject({ applied: 3, intent: { op: "op1", state: "closed" } });
	});
});

describe("what a replica does not run", () => {
	it("takes in, claims and ends nothing of an intent whose kind it has no registration of", async () => {
		const unaware = world.replica("w3", { kinds: [issue] });
		await decideKey();
		await world.w1.send({ flow, op: "res1", stage: keyStage(flow, reservation), prev: 0 });
		world.log.judge(flow, 1, verified);
		world.store.clock.set(leaseMs);
		expect(await unaware.step({ flow })).toEqual({ refused: "stuck" });
		expect(await unaware.tend(flow)).toEqual({ stepped: 0 });
		expect(world.frame()).toMatchObject({ applied: 0, intent: { state: "pending" } });
		expect(world.res().state).toBe("verified");
		expect(await world.w2.tend(flow)).toEqual({ stepped: 1 });
		expect(world.res().state).toBe("active");
	});

	it("refuses every event on a flow neither a subject's nor a client's", async () => {
		const client = { of: "publisher", id: "p1" } as const;
		const decide = () => ({ digest: "d".padEnd(43, "0"), eff: {}, records: [] });
		expect(await world.w1.decide({ kind: "issue", flow: client, op: "o", decide })).toEqual({
			refused: "notSubject",
		});
		const stage = { ...bundleStage("o"), flow: client };
		expect(await world.w1.send({ flow: client, op: "o", stage, prev: 0 })).toEqual({
			refused: "notSubject",
		});
		expect(await world.w1.rebase({ flow: client, op: "o", recheck: () => true })).toEqual({
			refused: "notSubject",
		});
		expect(await world.w1.step({ flow: client })).toEqual({ refused: "notSubject" });
		expect(await world.w1.tend(client)).toEqual({ refused: "notSubject" });
		expect(
			await world.w1.changeHeld({ kind: "key", flow: client, records: [], change: () => [] }),
		).toEqual({ refused: "notSubject" });
		expect(world.log.sent).toEqual([]);
	});

	it("rebases no op with no stage on the flow: its first stage is not put again (A16)", async () => {
		await decideIssue();
		expect(await world.w1.rebase({ flow, op: "op1", recheck: () => true })).toEqual({
			refused: "unplaced",
		});
	});

	it("changes no record of a part not the kind's own", async () => {
		await expect(
			world.w1.changeHeld({ kind: "issue", flow, records: [reservationRecord], change: () => [] }),
		).rejects.toThrow(TypeError);
	});

	it("marks an orphan its taker could not end, rather than taking it over again", async () => {
		const refusing = world.replica("w2", {
			log: (l) => ({
				...l,
				append: async () => ({ v: 1, result: "refused", refusal: "holdLimit" }),
			}),
		});
		await decideKey();
		world.store.clock.set(leaseMs);
		expect(await refusing.tend(flow)).toMatchObject({
			did: "tookOver",
			answer: { refusal: "holdLimit" },
		});
		world.store.clock.set(2 * leaseMs);
		expect(await world.w3.tend(flow)).toEqual({ stepped: 0, did: "marked" });
		expect(world.frame()).toMatchObject({ intent: { state: "abandoning", by: "w3" } });
	});
});

describe("a reset", () => {
	const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const instruction = (over: Record<string, unknown> = {}) =>
		`${b64({ alg: "ES256", typ: "reset-instruction+jwt" })}.${b64({
			v: 1,
			installation: "inst-1",
			subject: flow.id,
			action: "reset",
			kg: 0,
			id: "A".repeat(22),
			iat: 1,
			exp: 600,
			...over,
		})}.c2ln`;

	beforeEach(() => {
		world = makeWorld();
	});

	it("hands an instruction to the log and the Core takes its boundary in, the key generation on", async () => {
		const placed = await world.w1.reset({ instruction: instruction() });
		expect(placed).toMatchObject({ answer: { result: "accepted", position: 1 } });
		await world.w3.step({ flow });
		expect(world.part("keys")).toEqual({ keyGeneration: 1, keys: {} });
	});

	it("answers the same instruction sent again as placed, and another under its id a conflict", async () => {
		const first = await world.w1.reset({ instruction: instruction() });
		expect(await world.w2.reset({ instruction: instruction() })).toEqual(first);
		expect(await world.w1.reset({ instruction: instruction({ kg: 1 }) })).toEqual({
			answer: { v: 1, result: "conflict" },
		});
		expect(await world.w1.reset({ instruction: "a.b.c" })).toEqual({
			answer: { v: 1, result: "invalid", fault: "shape" },
		});
	});

	it("looks a reset's op up on its own subject's flow: the same id under another subject is another reset", async () => {
		const first = await world.w1.reset({ instruction: instruction() });
		const elsewhere = await world.w1.reset({ instruction: instruction({ subject: "s2" }) });
		expect(elsewhere).toMatchObject({ answer: { result: "accepted", position: 1 } });
		expect(await world.w1.reset({ instruction: instruction() })).toEqual(first);
	});

	it("moves no key generation for a reset that does not take", async () => {
		world.log.judgeResets({ verdict: "verified", outcome: "didNotTake" });
		await world.w1.reset({ instruction: instruction() });
		await world.w3.step({ flow });
		expect(world.part("keys")).toEqual(seeded.keys);
	});
});

describe("a record the log answers off the wire's form", () => {
	it("is never taken in: its step is unavailable and the frame stays where it was", async () => {
		world.log.monitor(flow, "denial", {});
		// A log adapter that does not hold what it answers to the wire's form: here, a record id `__proto__`.
		const untrusting = world.replica("w9", {
			log: (l) => ({
				...l,
				writer: l.writer,
				digest: l.digest,
				append: l.append,
				head: l.head,
				of: l.of,
				reset: l.reset,
				at: async (f, position) => {
					const placed = await l.at(f, position);
					return placed && { ...placed, record: { ...placed.record, id: "__proto__" } };
				},
			}),
		});
		await expect(untrusting.step({ flow })).rejects.toSatisfy(isUnavailable);
		expect(world.frame()?.applied ?? 0).toBe(0);
		// A record whose reading throws is off the form as well: unavailable, never another failure.
		const throwing = world.replica("w8", {
			log: (l) => ({
				...l,
				writer: l.writer,
				digest: l.digest,
				append: l.append,
				head: l.head,
				of: l.of,
				reset: l.reset,
				at: async (f, position) => {
					const placed = await l.at(f, position);
					if (!placed) return placed;
					const record = Object.defineProperty({ ...placed.record }, "id", {
						get: () => {
							throw new Error("adapter fault");
						},
					});
					return { ...placed, record };
				},
			}),
		});
		await expect(throwing.step({ flow })).rejects.toSatisfy(isUnavailable);
		// Read as the log gave it, the same record is taken in.
		expect(await world.w1.step({ flow })).toMatchObject({ position: 1 });
	});
});

describe("what a log's adapter answers, held to the wire's forms", () => {
	const through = (at?: TransparencyLog["at"], append?: TransparencyLog["append"]) =>
		world.replica("w1", {
			log: (l) => ({
				writer: l.writer,
				digest: (preimage) => l.digest(preimage),
				append: append ?? ((stage, prev) => l.append(stage, prev)),
				head: (f) => l.head(f),
				of: (f, op) => l.of(f, op),
				reset: (instruction) => l.reset(instruction),
				at: at ?? ((f, position) => l.at(f, position)),
			}),
		});

	it("takes in a record whose finding and changes the adapter gives by getters, as any other", async () => {
		world.log.monitor(flow, "denial", { revoke: "k1" });
		const t = through(async (f, position) => {
			const placed = await world.log.as("w1").at(f, position);
			if (!placed) return placed;
			const { finding, changes } = placed;
			const inherited = Object.create({
				get finding() {
					return finding;
				},
				get changes() {
					return changes;
				},
			});
			return Object.assign(inherited, { record: placed.record });
		});
		expect(await t.step({ flow })).toEqual({ position: 1 });
		expect(world.part("keys").keys).toEqual({});
	});

	it("answers unavailable for a record at another position than asked, or a tick, taking in nothing", async () => {
		world.log.monitor(flow, "denial", { revoke: "k1" });
		const moved = through(async (f, position) => {
			const placed = await world.log.as("w1").at(f, position);
			return placed && ({ ...placed, record: { ...placed.record, position: 2 } } as never);
		});
		await expect(moved.step({ flow })).rejects.toSatisfy(isUnavailable);
		const tick = through(
			async () =>
				({
					record: {
						v: 1,
						id: "t1",
						writer: { role: "log" },
						kind: "tick",
						shard: "s1",
						n: 1,
						acceptedAt: 1,
					},
					finding: verified,
				}) as never,
		);
		await expect(tick.step({ flow })).rejects.toSatisfy(isUnavailable);
		expect(world.frame()?.applied ?? 0).toBe(0);
	});

	it("answers unavailable for an accepted append answer off the form", async () => {
		const t = through(undefined, async (stage, prev) => {
			const answer = await world.log.as("w1").append(stage, prev);
			return { ...answer, extra: 1 } as never;
		});
		expect(
			await t.decide({
				kind: "issue",
				flow,
				op: "o9",
				decide: () => ({ digest: "d".repeat(43), eff: {}, records: [] }),
			}),
		).toMatchObject({ prev: 0 });
		await expect(
			t.send({ flow, op: "o9", stage: { ...bundleStage("o9"), stage: 1, last: false }, prev: 0 }),
		).rejects.toSatisfy(isUnavailable);
	});
});
