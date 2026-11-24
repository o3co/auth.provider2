import type { Changes, Finding } from "@mod/authority-rules";
import { opIds } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	type At,
	abandonStage,
	closedByOwner,
	decided,
	type Frame,
	frameOf,
	isOrphan,
	isOwner,
	marked,
	rebased,
	stepped,
	type Taken,
	takenOver,
	whileClosed,
} from "../frame.ts";

const leaseMs = 5000;
const at = (replica: string, now: number, generation = 1): At => ({ replica, generation, now });
const verified: Finding = { verdict: "verified", outcome: "took" };
const didNotTake: Finding = { verdict: "verified", outcome: "didNotTake" };
const held: Finding = { verdict: "held", outcome: "took" };
const family: Changes = { family: { approval: "a1" } };
const bundles = (kind: string) => kind === "issue";
const fresh = frameOf(undefined, 1);
/** What the log holds of an op: nothing, or its last stage. */
const none = { stages: 0, last: false, abandonments: 0 };
const lastOn = { stages: 1, last: true, abandonments: 0 };

/** The frame with an op decided by w1 at time 0: a bundle op (`issue`) or a key change (`key`). */
function decidedBy(kind: "issue" | "key", frame: Frame = fresh, op = "op1"): Frame {
	const next = decided(frame, at("w1", 0), {
		op,
		kind,
		digest: "d1",
		eff: kind === "issue" ? family : {},
		head: frame.applied,
		placed: none,
		leaseMs,
	});
	if (!("frame" in next)) throw new Error(`not decided: ${next.refused}`);
	return next.frame;
}
const core = (position: number, op: string, last: boolean, finding = verified): Taken => ({
	id: `r${position}`,
	role: "core",
	kind: last ? "bundle" : "start",
	op,
	last,
	position,
	finding,
});
const keyRecord = (position: number, op: string, finding = verified): Taken => ({
	...core(position, op, true, finding),
	kind: "keyChange",
});
const abandonment = (position: number, of: string, attempt: number, finding = verified): Taken => ({
	id: `r${position}`,
	role: "core",
	kind: "abandonment",
	op: opIds.abandonment(of, attempt),
	last: true,
	position,
	abandons: { op: of, attempt },
	finding,
});
const monitor = (position: number, changes: Changes = {}): Taken => ({
	id: `r${position}`,
	role: "monitor",
	kind: "denial",
	op: `m${position}`,
	last: true,
	position,
	finding: verified,
	changes,
});
function step(frame: Frame, who: At, r: Taken, own = false) {
	const next = stepped(frame, who, r, { own, bundle: bundles });
	if (!("frame" in next)) throw new Error(`not stepped: ${next.refused}`);
	return next;
}

describe("KE-C01, deciding an op", () => {
	it("writes one pending intent at the applied position, its lease ending on the store clock", () => {
		const frame = decidedBy("issue");
		expect(frame.intent).toEqual({
			op: "op1",
			kind: "issue",
			state: "pending",
			prev: 0,
			digest: "d1",
			eff: family,
			by: "w1",
			leaseEnd: leaseMs,
			generation: 1,
			family: null,
			taken: false,
		});
		expect(frame.applied).toBe(0);
	});

	it("decides nothing while the flow is not taken in to its head, an intent is open, or the frame is another generation's", () => {
		const ask = { op: "op2", kind: "issue", digest: "d", eff: {}, placed: none, leaseMs };
		expect(decided(fresh, at("w1", 0), { ...ask, head: 1 })).toEqual({ refused: "notReady" });
		const open = decidedBy("issue");
		expect(decided(open, at("w2", 9000), { ...ask, head: 0 })).toEqual({ refused: "open" });
		const abandoning = marked(open, at("w2", 9000), 0);
		if (!("frame" in abandoning)) throw new Error("not marked");
		expect(decided(abandoning.frame, at("w2", 9000), { ...ask, head: 0 })).toEqual({
			refused: "open",
		});
		expect(decided(fresh, at("w1", 0, 2), { ...ask, head: 0 })).toEqual({ refused: "sealed" });
	});

	it("never decides an op whose last stage is on the flow, whatever its judgment or the ops since (~InLogKey)", () => {
		const again = { op: "op1", kind: "key", digest: "d1", eff: {}, head: 1, leaseMs };
		for (const finding of [verified, didNotTake, held]) {
			const ended = step(decidedBy("key"), at("w1", 100), keyRecord(1, "op1", finding), true);
			expect(decided(ended.frame, at("w1", 200), { ...again, placed: lastOn })).toEqual({
				refused: "ended",
			});
			// Another op decided and ended between: the frame no longer names op1, the flow does.
			const other = decidedBy("key", ended.frame, "op2");
			const between = step(other, at("w1", 300), keyRecord(2, "op2"), true).frame;
			expect(between.intent?.op).toBe("op2");
			expect(decided(between, at("w1", 400), { ...again, head: 2, placed: lastOn })).toEqual({
				refused: "ended",
			});
		}
		const done = step(decidedBy("key"), at("w1", 100), keyRecord(1, "op1"), true).frame;
		expect("frame" in decided(done, at("w1", 200), { ...again, op: "op2", placed: none })).toBe(
			true,
		);
	});

	it("decides an op again after its empty abandonment closed it (W_ReDecided)", () => {
		const orphan = marked(decidedBy("key"), at("w2", 6000), 0);
		if (!("frame" in orphan)) throw new Error("not marked");
		const closed = step(orphan.frame, at("w2", 6100), abandonment(1, "op1", 1)).frame;
		expect(closed.intent?.state).toBe("closed");
		const again = decided(closed, at("w1", 7000), {
			op: "op1",
			kind: "key",
			digest: "d1",
			eff: {},
			head: 1,
			placed: { stages: 0 },
			leaseMs,
		});
		if (!("frame" in again)) throw new Error("not decided");
		expect(again.frame.intent).toMatchObject({ state: "pending", prev: 1 });
	});

	it("never decides again an op whose first stage was placed, even after its abandonment closed it (A16)", () => {
		const orphan = marked(decidedBy("key"), at("w2", 6000), 0);
		if (!("frame" in orphan)) throw new Error("not marked");
		const closed = step(orphan.frame, at("w2", 6100), abandonment(1, "op1", 1)).frame;
		expect(closed.intent?.state).toBe("closed");
		// The log answers what the flow holds of op1: here a first stage before its abandonment.
		const ask = { op: "op1", kind: "key", digest: "d1", eff: {}, head: 1, leaseMs };
		const placed = { stages: 1, last: false, abandonments: 1 };
		expect(decided(closed, at("w1", 7000), { ...ask, placed })).toEqual({ refused: "ended" });
	});
});

describe("the owner rule", () => {
	it("an owner is the intent's writer, pending, while its lease holds on the store clock", () => {
		const it = decidedBy("issue").intent;
		expect(isOwner(it, at("w1", leaseMs - 1))).toBe(true);
		expect(isOwner(it, at("w1", leaseMs))).toBe(false);
		expect(isOwner(it, at("w2", 1))).toBe(false);
		expect(isOrphan(it, at("w2", leaseMs - 1))).toBe(false);
		expect(isOrphan(it, at("w2", leaseMs))).toBe(true);
	});

	it("only a live owner closes without a record, by a write held before its lease ends (CloseNoLease)", () => {
		const frame = decidedBy("issue");
		const closed = closedByOwner(frame, at("w1", 10), "op1");
		expect(closed).toMatchObject({
			frame: { intent: { state: "closed", eff: null } },
			ownerUntil: leaseMs - 1,
			end: { op: "op1", kind: "issue", ending: "refused", owner: true },
		});
		expect(closedByOwner(frame, at("w1", leaseMs), "op1")).toEqual({ refused: "notOwner" });
		expect(closedByOwner(frame, at("w2", 10), "op1")).toEqual({ refused: "notOwner" });
		expect(closedByOwner(frame, at("w1", 10), "op9")).toEqual({ refused: "notOwner" });
	});

	it("a lease-less writer of the intent is no owner, though by names it (IdleLoose)", () => {
		const frame = decidedBy("key");
		expect(rebased(frame, at("w1", leaseMs + 1), "op1", 0)).toEqual({ refused: "notOwner" });
		expect(
			stepped(frame, at("w1", leaseMs + 1), keyRecord(1, "op1"), { own: true, bundle: bundles }),
		).toMatchObject({ end: { owner: false } });
	});

	it("the owner moves its previous position to the head it took in, to resend the next stage", () => {
		const frame = step(decidedBy("issue"), at("w1", 10), core(1, "op1", false)).frame;
		const withMon = step(frame, at("w1", 20), monitor(2)).frame;
		expect(rebased(withMon, at("w1", 30), "op1", 2)).toMatchObject({
			frame: { intent: { prev: 2 } },
			ownerUntil: leaseMs - 1,
		});
		expect(rebased(withMon, at("w1", 30), "op1", 3)).toEqual({ refused: "notReady" });
	});
});

describe("KE-C04, the one Step", () => {
	it("takes in another writer's record by any replica, the intent unchanged, with its body's changes", () => {
		const frame = decidedBy("issue");
		const next = step(frame, at("w2", 10), monitor(1, { revoke: "k1" }));
		expect(next.frame).toEqual({ ...frame, applied: 1 });
		expect(next.changes).toEqual({ revoke: "k1" });
		expect(next.end).toBeUndefined();
	});

	it("takes in a record of a flow with no intent, sealed by the stepper's generation", () => {
		expect(step(fresh, at("w2", 10), monitor(1)).frame).toEqual({
			applied: 1,
			generation: 1,
			intent: null,
		});
	});

	it("leaves a live owner's records to it: another replica waits, the owner takes its last stage only in apply", () => {
		const frame = decidedBy("issue");
		const start = core(1, "op1", false);
		expect(stepped(frame, at("w2", 10), start, { own: false, bundle: bundles })).toEqual({
			refused: "waits",
		});
		const started = step(frame, at("w1", 10), start);
		expect(started.frame.intent).toEqual(frame.intent);
		// The op's changes are its last stage's: its start, an earlier stage, changes nothing.
		expect(started.changes).toEqual({});
		expect(started.ownerUntil).toBe(leaseMs - 1);
		const last = core(2, "op1", true);
		expect(stepped(started.frame, at("w1", 20), last, { own: false, bundle: bundles })).toEqual({
			refused: "waits",
		});
		const done = step(started.frame, at("w1", 20), last, true);
		expect(done.changes).toEqual(family);
		expect(done.frame.intent).toMatchObject({ state: "done", eff: null });
		expect(done.end).toEqual({ op: "op1", kind: "issue", ending: "took", owner: true });
		expect(done.ownerUntil).toBe(leaseMs - 1);
	});

	it("closes the owner's bundle that did not take, or was held, giving no tokens", () => {
		const frame = decidedBy("issue");
		const failed = step(frame, at("w1", 10), core(1, "op1", true, didNotTake), true);
		expect(failed.frame.intent?.state).toBe("closed");
		expect(failed.end).toMatchObject({ ending: "didNotTake", owner: true });
		const heldBundle = step(frame, at("w1", 10), core(1, "op1", true, held), true);
		expect(heldBundle.frame.intent?.state).toBe("closed");
		expect(heldBundle.end).toMatchObject({ ending: "held", owner: true });
	});

	it("marks a bundle left alone abandoning, by the stepper, remembering the family it made (A40)", () => {
		const frame = decidedBy("issue");
		const left = step(frame, at("w2", leaseMs), core(1, "op1", true));
		expect(left.frame.intent).toMatchObject({ state: "abandoning", by: "w2", family: "r1" });
		expect(left.end).toBeUndefined();
		expect(left.ownerUntil).toBeUndefined();
	});

	it("keeps an abandoning op abandoning when its late bundle lands, taking its family", () => {
		const orphan = marked(decidedBy("issue"), at("w2", leaseMs), 0);
		if (!("frame" in orphan)) throw new Error("not marked");
		const late = step(orphan.frame, at("w1", leaseMs + 1), {
			...core(1, "op1", true),
			kind: "bundle",
		});
		expect(late.frame.intent).toMatchObject({ state: "abandoning", by: "w2", family: "r1" });
	});

	it("names a rotated family as what a bundle left alone made", () => {
		const frame = decided(fresh, at("w1", 0), {
			op: "op1",
			kind: "issue",
			digest: "d1",
			eff: { rotate: "f0" },
			head: 0,
			placed: none,
			leaseMs,
		});
		if (!("frame" in frame)) throw new Error("not decided");
		expect(step(frame.frame, at("w2", leaseMs), core(1, "op1", true)).frame.intent?.family).toBe(
			"f0",
		);
	});

	it("ends a key change at its last stage alike, owner or not, pending or abandoning (fix4)", () => {
		const owner = step(decidedBy("key"), at("w1", 10), keyRecord(1, "op1"), true);
		expect(owner.end).toEqual({ op: "op1", kind: "key", ending: "took", owner: true });
		const orphan = step(decidedBy("key"), at("w2", leaseMs), keyRecord(1, "op1", didNotTake));
		expect(orphan.frame.intent).toMatchObject({ state: "closed" });
		expect(orphan.end).toEqual({ op: "op1", kind: "key", ending: "didNotTake", owner: false });
		const markedKey = marked(decidedBy("key"), at("w2", leaseMs), 0);
		if (!("frame" in markedKey)) throw new Error("not marked");
		const late = step(markedKey.frame, at("w1", leaseMs + 1), keyRecord(1, "op1", held));
		expect(late.frame.intent).toMatchObject({ state: "closed", eff: null });
		expect(late.end).toMatchObject({ ending: "held", owner: false });
	});

	it("closes the op on its verified abandonment, dropping its family; a held one changes no intent", () => {
		const left = step(decidedBy("issue"), at("w2", leaseMs), core(1, "op1", true)).frame;
		const held1 = step(left, at("w1", leaseMs + 1), abandonment(2, "op1", 1, held));
		expect(held1.frame.intent).toEqual(left.intent);
		expect(held1.changes).toEqual({ abandon: "r1" });
		expect(held1.end).toBeUndefined();
		const closed = step(held1.frame, at("w2", leaseMs + 2), abandonment(3, "op1", 2));
		expect(closed.frame.intent).toMatchObject({ state: "closed", eff: null });
		expect(closed.end).toEqual({ op: "op1", kind: "issue", ending: "abandoned", owner: false });
	});

	it("gives an empty abandonment no family to drop", () => {
		const orphan = marked(decidedBy("issue"), at("w2", leaseMs), 0);
		if (!("frame" in orphan)) throw new Error("not marked");
		expect(step(orphan.frame, at("w2", leaseMs), abandonment(1, "op1", 1)).changes).toEqual({});
	});

	it("takes in no Core record of an ended intent or another op: the flow waits (OfIt)", () => {
		const done = step(decidedBy("key"), at("w1", 10), keyRecord(1, "op1"), true).frame;
		expect(
			stepped(done, at("w2", 20), keyRecord(2, "op1"), { own: false, bundle: bundles }),
		).toEqual({ refused: "stuck" });
		const open = decidedBy("key");
		expect(
			stepped(open, at("w2", 20), keyRecord(1, "op9"), { own: false, bundle: bundles }),
		).toEqual({ refused: "stuck" });
		expect(
			stepped(fresh, at("w2", 20), keyRecord(1, "op9"), { own: false, bundle: bundles }),
		).toEqual({ refused: "stuck" });
	});

	it("moves one position at a time, on a frame of the stepper's generation (NoSkip, SealedOK)", () => {
		expect(stepped(fresh, at("w1", 0), monitor(2), { own: false, bundle: bundles })).toEqual({
			refused: "notNext",
		});
		expect(stepped(fresh, at("w1", 0, 2), monitor(1), { own: false, bundle: bundles })).toEqual({
			refused: "sealed",
		});
	});

	it("passes no changes for the op's noEffect record", () => {
		const frame = decidedBy("issue");
		const next = step(
			frame,
			at("w1", 10),
			{ ...core(1, "op1", true, didNotTake), kind: "noEffect" },
			true,
		);
		expect(next.changes).toEqual({});
		expect(next.frame.intent?.family).toBeNull();
	});

	it("ends an op whose last stage is a noEffect as not taken, however the noEffect is judged, but held", () => {
		const noEffect = (finding: Finding): Taken => ({
			...core(1, "op1", true, finding),
			kind: "noEffect",
		});
		const took = step(decidedBy("issue"), at("w1", 10), noEffect(verified), true);
		expect(took.end).toEqual({ op: "op1", kind: "issue", ending: "didNotTake", owner: true });
		expect(took.frame.intent?.state).toBe("closed");
		const heldOne = step(decidedBy("issue"), at("w1", 10), noEffect(held), true);
		expect(heldOne.end).toMatchObject({ ending: "held" });
	});
});

describe("KE-C14 and KE-C10, claiming an orphan", () => {
	it("marks an orphan abandoning by the marker, once the flow is taken in to its head", () => {
		const frame = decidedBy("issue");
		expect(marked(frame, at("w2", leaseMs - 1), 0)).toEqual({ refused: "notOrphan" });
		expect(marked(frame, at("w2", leaseMs), 1)).toEqual({ refused: "notReady" });
		const next = marked(frame, at("w2", leaseMs), 0);
		expect(next).toMatchObject({ frame: { intent: { state: "abandoning", by: "w2" } } });
		if (!("frame" in next)) throw new Error("not marked");
		expect(marked(next.frame, at("w1", leaseMs + 1), 0)).toEqual({ refused: "notOrphan" });
	});

	it("takes over an orphan that is no bundle, with a lease of its own; never a bundle (A40), never once marked (ClaimExclusive)", () => {
		const key = decidedBy("key");
		expect(takenOver(key, at("w2", leaseMs - 1), { leaseMs, bundle: bundles })).toEqual({
			refused: "notOrphan",
		});
		expect(takenOver(key, at("w2", leaseMs), { leaseMs, bundle: bundles })).toMatchObject({
			frame: {
				intent: { state: "pending", by: "w2", leaseEnd: 2 * leaseMs, prev: 0, taken: true },
			},
		});
		expect(takenOver(decidedBy("issue"), at("w2", leaseMs), { leaseMs, bundle: bundles })).toEqual({
			refused: "bundle",
		});
		const claimed = marked(key, at("w2", leaseMs), 0);
		if (!("frame" in claimed)) throw new Error("not marked");
		expect(takenOver(claimed.frame, at("w1", leaseMs), { leaseMs, bundle: bundles })).toEqual({
			refused: "notOrphan",
		});
	});

	it("keeps the intent and its changes past its lease: the lease ends, the intent stays", () => {
		const frame = decidedBy("issue");
		expect(frame.intent?.eff).toEqual(family);
		expect(isOrphan(frame.intent, at("w2", 10 * leaseMs))).toBe(true);
		const claimed = marked(frame, at("w2", 10 * leaseMs), 0);
		expect(claimed).toMatchObject({ frame: { intent: { eff: family, digest: "d1" } } });
	});
});

describe("KE-C09, the abandonment record", () => {
	it("is sent only for an abandoning op, at the head the same read shows (AbnNoMark)", () => {
		const frame = decidedBy("issue");
		expect(abandonStage(frame, at("w2", leaseMs), 0, none)).toEqual({ refused: "notAbandoning" });
		const claimed = marked(frame, at("w2", leaseMs), 0);
		if (!("frame" in claimed)) throw new Error("not marked");
		expect(abandonStage(claimed.frame, at("w1", leaseMs), 1, none)).toEqual({
			refused: "notReady",
		});
		expect(abandonStage(claimed.frame, at("w1", leaseMs), 0, none)).toEqual({
			op: opIds.abandonment("op1", 1),
			abandons: { op: "op1", attempt: 1, digest: "d1" },
			prev: 0,
		});
	});

	it("counts its attempts from the op's abandonment records on the flow, whichever intents sent them", () => {
		const left = step(decidedBy("issue"), at("w2", leaseMs), core(1, "op1", true)).frame;
		const held1 = step(left, at("w1", leaseMs), abandonment(2, "op1", 1, held)).frame;
		const onFlow = { stages: 1, last: true, abandonments: 1 };
		expect(abandonStage(held1, at("w1", leaseMs), 2, onFlow)).toMatchObject({
			op: opIds.abandonment("op1", 2),
			abandons: { attempt: 2 },
			prev: 2,
		});
	});
});

describe("a change held to the frame", () => {
	it("goes through only while the flow has no open intent (Cancel, Retry: ~OpenI)", () => {
		expect(whileClosed(fresh, at("w1", 0))).toEqual({ closed: true });
		expect(whileClosed(decidedBy("key"), at("w1", 0))).toEqual({ refused: "open" });
		const done = step(decidedBy("key"), at("w1", 10), keyRecord(1, "op1"), true).frame;
		expect(whileClosed(done, at("w1", 20))).toEqual({ closed: true });
	});
});

describe("the frame as stored", () => {
	it("reads back what it wrote, and refuses a value of another shape", () => {
		const frame = decidedBy("issue");
		expect(frameOf(JSON.parse(JSON.stringify(frame)), 1)).toEqual(frame);
		expect(() => frameOf({ applied: -1 }, 1)).toThrow(TypeError);
	});
});
