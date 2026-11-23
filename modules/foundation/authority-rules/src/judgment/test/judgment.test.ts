import { describe, expect, it } from "vitest";
import {
	approval,
	codeBundle,
	codeStart,
	firstKey,
	login,
	prefixOf,
	refreshBundle,
	refreshStart,
	type Step,
} from "../../../test/fixtures/flow.ts";
import {
	authorization,
	checks,
	context,
	coreRecord,
	type FlowRecord,
	limits,
	monitorRecord,
	preimage,
} from "../../../test/fixtures/world.ts";
import { emptyState, type Finding, type FlowEntry, fold } from "../../fold/fold.ts";
import { judge, outcomeOf, type Reading } from "../judgment.ts";

// Each case names the row of kernel-spec §6.1 (J0–J13) or §6.2 it is taken from, and the model's
// regressions of §9.3 (K_reg_*) and BundleEscape023 it must refuse.

type Prefix = ReturnType<typeof prefixOf>;
const on = (steps: (Step & { judgment?: Finding })[]): Prefix => prefixOf(steps);
const empty: Prefix = { state: emptyState, prior: [] };
const readingOf = (step: Step, p: Prefix, over: Partial<Reading> = {}): Reading => ({
	record: step.record,
	opening: { opened: step.preimage },
	keySets: { ever: ["mk-0", "mk-1"], atRecord: ["mk-1"] },
	versions: {},
	state: p.state,
	prior: p.prior,
	checks,
	context: context(),
	...over,
});
const ruled = (step: Step, p: Prefix, over: Partial<Reading> = {}) =>
	judge(readingOf(step, p, over));
const held = { verdict: "held", outcome: "didNotTake" } as const;
const verdictOf = (r: ReturnType<typeof judge>) =>
	"wait" in r ? r : { row: r.row, verdict: r.entry.judgment.verdict, counted: r.counted };

describe("J0: a monitor's, publisher's or the people's record", () => {
	it("is verified and took, its changes from its body, a confirmation's or denial's registration its parent", () => {
		const denial = judge({
			...readingOf({ record: monitorRecord("denial", 3), preimage: {} }, empty),
			opening: undefined,
			body: { v: 1, registration: "r-1" },
		});
		expect(denial).toMatchObject({
			row: "J0",
			counted: false,
			entry: {
				changes: { revoke: "r-1" },
				judgment: { verdict: "verified", outcome: "took" },
				parent: "r-1",
			},
		});
		const conf = judge({
			...readingOf({ record: monitorRecord("confirmation", 3), preimage: {} }, empty),
			body: { v: 1, registration: "r-1" },
		});
		expect(conf).toMatchObject({ row: "J0", entry: { changes: {}, parent: "r-1" } });
	});

	it("is forged where a writer that is no Core writer names a Core writer's kind (J2: 書き手の種類と記録の種類が合わない)", () => {
		const r = monitorRecord("bundle", 3);
		expect(
			verdictOf(judge({ ...readingOf({ record: r, preimage: {} }, empty), body: {} })),
		).toEqual({
			row: "J2",
			verdict: "forged",
			counted: false,
		});
	});
	it("refuses, as a TypeError, a Core writer's record read without its opening or key sets", () => {
		expect(() => ruled(firstKey(1), empty, { opening: undefined })).toThrow(TypeError);
		expect(() => ruled(firstKey(1), empty, { keySets: undefined })).toThrow(TypeError);
	});
});

describe("J1 and J6: a temporary failure", () => {
	const failing = (elapsed: number) => ({ failing: { since: 10_000, now: 10_000 + elapsed } });
	it("waits while it lasts less than T_retry, and is held, not counted, from then on (K_reg_tempAsHold)", () => {
		expect(ruled(firstKey(1), empty, { opening: failing(limits.retry - 1) })).toEqual({
			wait: "temporary",
		});
		expect(verdictOf(ruled(firstKey(1), empty, { opening: failing(limits.retry) }))).toEqual({
			row: "J6",
			verdict: "held",
			counted: false,
		});
	});

	it("waits for a version's acceptance time it does not know yet (WaitVer)", () => {
		const step = {
			...firstKey(1),
			record: { ...firstKey(1).record, configVersion: 2 } as FlowRecord,
		};
		expect(ruled(step, empty)).toEqual({ wait: "version" });
	});
});

describe("J2–J5: what the envelope and the opening tell", () => {
	it("forges a Core writer's record of a kind no Core writer writes (J2)", () => {
		const step = { record: coreRecord("denial", 1), preimage: preimage({}) };
		expect(verdictOf(ruled(step, empty))).toMatchObject({ row: "J2", verdict: "forged" });
	});

	it("forges a second start from one approval whatever the first one's verdict (J2), before J5", () => {
		const p = on([
			firstKey(1),
			approval(2, "r-1"),
			{ ...codeStart(3, "login", "r-2"), judgment: held },
		]);
		expect(verdictOf(ruled(codeStart(4, "again", "r-2"), p))).toMatchObject({
			row: "J2",
			verdict: "forged",
		});
	});

	it("forges a record sealed to a key never in a key set (J3; K_reg_keySetNoRefuse)", () => {
		const step = {
			...firstKey(1),
			record: {
				...firstKey(1).record,
				sealedTo: [{ key: "mk-9", ciphertextHash: "c".repeat(43) }],
			} as FlowRecord,
		};
		expect(verdictOf(ruled(step, empty))).toMatchObject({ row: "J3", verdict: "forged" });
	});

	it("forges a preimage that does not decrypt or verify, or is not the wire's form (J4)", () => {
		expect(
			verdictOf(ruled(firstKey(1), empty, { opening: { undecryptable: true } })),
		).toMatchObject({ row: "J4", verdict: "forged" });
		expect(verdictOf(ruled(firstKey(1), empty, { opening: { opened: { v: 1 } } }))).toMatchObject({
			row: "J4",
			verdict: "forged",
		});
	});

	it("holds, not counted, a damaged or lost preimage, before the chain (J5 before J7)", () => {
		for (const missing of ["damaged", "lost"] as const)
			expect(verdictOf(ruled(approval(2, "r-9"), empty, { opening: { missing } }))).toEqual({
				row: "J5",
				verdict: "held",
				counted: false,
			});
	});
});

describe("J7: the chain", () => {
	it("forges a record the chain refuses, with the rule broken, and checks the chain before the time (K_reg_timeFirst)", () => {
		const late = approval(2, "r-9");
		const r = ruled(
			{ ...late, record: { ...late.record, acceptedAt: (authorization("sid-1").exp + 10) * 1000 } },
			on([firstKey(1)]),
		);
		expect(r).toMatchObject({
			row: "J7",
			entry: { judgment: { verdict: "forged", outcome: "didNotTake" } },
			reason: expect.stringMatching(/not live/),
		});
	});

	it("forges a broken bundle after a held start: forged goes before the inherited hold (K_reg_inheritOverBad)", () => {
		const steps = login();
		const p = on([...steps.slice(0, 2), { ...(steps[2] as Step), judgment: held }]);
		expect(verdictOf(ruled(codeBundle(4, "login", "r-3", "r-9"), p))).toMatchObject({
			row: "J7",
			verdict: "forged",
		});
	});

	it("forges a bundle whose start came after the code's lifetime even when the start is held (BundleEscape023 `startA` at J7, before J9)", () => {
		const steps = login();
		const start = steps[2] as Step;
		const late = {
			...start,
			record: {
				...start.record,
				acceptedAt: (steps[1] as Step).record.acceptedAt + limits.codeLifetime + 1,
			},
		};
		const p = on([...steps.slice(0, 2), { ...late, judgment: held }]);
		expect(verdictOf(ruled(steps[3] as Step, p))).toMatchObject({ row: "J7", verdict: "forged" });
	});
});

describe("J8 and J10: the version's window (K6)", () => {
	const versioned = (at: number) => {
		const step = firstKey(1);
		return {
			...step,
			record: { ...step.record, registryVersion: 3, acceptedAt: at } as FlowRecord,
		};
	};
	const { epsilon: e, propagation: P } = limits;
	const b = 1_700_000_000_000;

	it("forges a record before its version's lower bound b(v) − ε, and not at it (J8; K_reg_noLowerEps)", () => {
		const window = { versions: { registry: { at: b } } };
		expect(verdictOf(ruled(versioned(b - e - 1), empty, window))).toMatchObject({
			row: "J8",
			verdict: "forged",
		});
		expect(verdictOf(ruled(versioned(b - e), empty, window))).not.toMatchObject({ row: "J8" });
	});

	it("holds and counts a record past b(v+1) + P + ε, and not before it (J10; K_reg_noUpperEps, K_reg_propIncl)", () => {
		const window = { versions: { registry: { at: b - 10_000, next: b } } };
		expect(verdictOf(ruled(versioned(b + P + e), empty, window))).toEqual({
			row: "J10",
			verdict: "held",
			counted: true,
		});
		expect(verdictOf(ruled(versioned(b + P + e - 1), empty, window))).toEqual({
			row: "J12",
			verdict: "unsupported",
			counted: false,
		});
	});
});

describe("J9: the same op's earlier stage held", () => {
	it("holds, not counted, a sound bundle after a held start, and never forges it (K_reg_noInherit; KG-01)", () => {
		const steps = login();
		const p = on([...steps.slice(0, 2), { ...(steps[2] as Step), judgment: held }]);
		expect(verdictOf(ruled(steps[3] as Step, p))).toEqual({
			row: "J9",
			verdict: "held",
			counted: false,
		});
	});

	it("holds before J10, so an inherited hold is not counted (KG-21)", () => {
		const steps = login();
		const p = on([...steps.slice(0, 2), { ...(steps[2] as Step), judgment: held }]);
		const b = steps[3] as Step;
		const stale = { ...b, record: { ...b.record, registryVersion: 1 } as FlowRecord };
		const window = { versions: { registry: { at: 0, next: 1 } } };
		expect(verdictOf(ruled(stale, p, window))).toEqual({
			row: "J9",
			verdict: "held",
			counted: false,
		});
	});

	it("does not carry a hold to another op of the flow (K_reg_holdSpreadsFlow)", () => {
		const steps = login();
		const p = on([...steps.slice(0, 3), { ...(steps[3] as Step), judgment: held }]);
		expect(p.state.families).toEqual({});
		const q = on([...steps, { ...refreshStart(5, "rf-1", "r-4"), judgment: held }]);
		expect(verdictOf(ruled(refreshStart(6, "rf-2", "r-4"), q))).toMatchObject({
			verdict: "unsupported",
		});
	});
});

describe("J11: a key that was in a set before", () => {
	it("holds, not counted, a record sealed only to keys out of its record's set", () => {
		const step = {
			...firstKey(1),
			record: {
				...firstKey(1).record,
				sealedTo: [{ key: "mk-0", ciphertextHash: "c".repeat(43) }],
			} as FlowRecord,
		};
		expect(verdictOf(ruled(step, empty))).toEqual({ row: "J11", verdict: "held", counted: false });
	});
});

describe("J12 and J13: the root", () => {
	it("gives a first-trust key and what roots in it unsupported until the key is confirmed (Rules023e InsuffAt)", () => {
		const steps = login();
		let p = empty;
		for (const [i, step] of steps.entries()) {
			expect(verdictOf(ruled(step, p))).toEqual({
				row: "J12",
				verdict: "unsupported",
				counted: false,
			});
			p = on(steps.slice(0, i + 1));
		}
	});

	it("verifies what follows the root's confirmation, a family made before it refreshed after it included (OI-21, W_RefOkAfterConf)", () => {
		const steps = login();
		const p = on(steps);
		const confirmed = {
			state: p.state,
			prior: [
				...p.prior,
				{
					envelope: {
						id: "r-5",
						kind: "confirmation",
						op: "op-5",
						stage: 1,
						last: true,
						position: 5,
						acceptedAt: 0,
					},
					changes: {},
					judgment: { verdict: "verified", outcome: "took" },
					parent: "r-1",
				} as const,
			],
		};
		expect(verdictOf(ruled(refreshStart(6, "rf-1", "r-4"), confirmed))).toEqual({
			row: "J13",
			verdict: "verified",
			counted: false,
		});
		expect(verdictOf(ruled(refreshStart(5, "rf-1", "r-4"), p))).toMatchObject({ row: "J12" });
		const otherRoot = {
			...confirmed,
			prior: confirmed.prior.map((e) =>
				e.envelope.kind === "confirmation" ? { ...e, parent: "r-9" } : e,
			),
		};
		expect(verdictOf(ruled(refreshStart(6, "rf-1", "r-4"), otherRoot))).toMatchObject({
			row: "J12",
		});
	});

	it("verifies an abandonment and a noEffect record, which rest on no root", () => {
		const abandonment = {
			record: coreRecord("abandonment", 5, {
				op: "abandonment:1:login",
				abandons: { op: "login", attempt: 1, digest: "p".repeat(43) },
			}),
			preimage: preimage({}),
		};
		expect(ruled(abandonment, on(login()))).toMatchObject({
			row: "J13",
			entry: { changes: { abandon: "r-4" }, judgment: { verdict: "verified", outcome: "took" } },
		});
		const steps = login();
		const p = on([
			...steps.slice(0, 2),
			{ ...(steps[2] as Step), judgment: { verdict: "unsupported", outcome: "didNotTake" } },
		]);
		const noEffect = {
			record: coreRecord("noEffect", 4, { op: "login", stage: 2 }),
			preimage: preimage({}),
		};
		expect(verdictOf(ruled(noEffect, p))).toEqual({
			row: "J13",
			verdict: "verified",
			counted: false,
		});
	});
});

/** Judges the steps in turn, each on the prefix the rulings before it made (as the monitor does). */
function judged(steps: readonly (Step & { over?: Partial<Reading> })[]) {
	let state = emptyState;
	const prior: FlowEntry[] = [];
	const rulings: ReturnType<typeof judge>[] = [];
	for (const step of steps) {
		const r = judge(readingOf(step, { state, prior }, step.over));
		rulings.push(r);
		if ("wait" in r) throw new Error("waits");
		prior.push(r.entry);
		state = fold(state, r.entry.envelope, r.entry.changes, r.entry.judgment);
	}
	return { state, prior, rulings };
}
const rowOf = (r: ReturnType<typeof judge> | undefined) =>
	r && !("wait" in r) ? `${r.row}:${r.entry.judgment.verdict}` : "none";

describe("review regressions (D4), judged in turn", () => {
	it("B1: forges a bundle after a start forged at J2, J7 or J8, and folds no family from it", () => {
		const a = judged([
			firstKey(1),
			approval(2, "r-1"),
			codeStart(3, "a", "r-2"),
			codeStart(4, "b", "r-2"),
			codeBundle(5, "b", "r-4", "r-2"),
		]);
		expect(a.rulings.map(rowOf).slice(3)).toEqual(["J2:forged", "J7:forged"]);
		expect(a.state.families).toEqual({});
		const b = judged([
			...login(),
			refreshStart(5, "rf", "r-4", 7),
			refreshBundle(6, "rf", "r-5", "r-4", 0),
		]);
		expect(b.rulings.map(rowOf).slice(4)).toEqual(["J7:forged", "J7:forged"]);
		expect(b.state.families["r-4"]?.rotation).toBe(0);
		const stale = codeStart(3, "login", "r-2");
		const c = judged([
			firstKey(1),
			approval(2, "r-1"),
			{
				...stale,
				record: { ...stale.record, registryVersion: 3 } as FlowRecord,
				over: { versions: { registry: { at: stale.record.acceptedAt + 10_000 } } },
			},
			codeBundle(4, "login", "r-3", "r-2"),
		]);
		expect(c.rulings.map(rowOf).slice(2)).toEqual(["J8:forged", "J7:forged"]);
		expect(c.state.families).toEqual({});
	});

	it("B2: forges a bundle naming another approval as its root after a start held at J10 (BundleEscape023 W_StaleStartLateBundle)", () => {
		const start = codeStart(4, "login", "r-2");
		const lateStale = {
			...start,
			record: {
				...start.record,
				configVersion: 1,
				acceptedAt: approval(2, "r-1").record.acceptedAt + limits.codeLifetime + 500,
			} as FlowRecord,
			over: { versions: { config: { at: 0, next: 1 } } },
		};
		const r = judged([
			firstKey(1),
			approval(2, "r-1"),
			approval(3, "r-1", "sid-2"),
			lateStale,
			codeBundle(5, "login", "r-4", "r-3"),
		]);
		expect(r.rulings.map(rowOf).slice(3)).toEqual(["J10:held", "J7:forged"]);
	});

	it("B3: forges a record whose writer's role does not write its kind, a Core kind or another role's, and folds nothing of it (J2)", () => {
		const p = on(login());
		const r = monitorRecord("denial", 5);
		const publisher = { ...r, writer: { role: "publisher", key: "pub-1" } } as FlowRecord;
		const ruling = judge({
			...readingOf({ record: publisher, preimage: {} }, p),
			body: { v: 1, registration: "r-1" },
		});
		expect(verdictOf(ruling)).toEqual({ row: "J2", verdict: "forged", counted: false });
		if ("wait" in ruling) throw new Error("waits");
		const e = ruling.entry;
		expect(fold(p.state, e.envelope, e.changes, e.judgment)).toBe(p.state);
		const people = {
			...monitorRecord("confirmation", 5),
			writer: { role: "human", keys: ["h-1"] },
		} as FlowRecord;
		expect(
			verdictOf(
				judge({
					...readingOf({ record: people, preimage: {} }, p),
					body: { v: 1, registration: "r-1" },
				}),
			),
		).toMatchObject({ row: "J2", verdict: "forged" });
	});

	it("Codex 1: forges a bundle after a start forged at J8, its root key confirmed (J7 不正な親の子孫)", () => {
		const conf = {
			record: monitorRecord("confirmation", 2),
			preimage: {},
			over: { body: { v: 1, registration: "r-1" } },
		};
		const stale = codeStart(4, "login", "r-3");
		const r = judged([
			firstKey(1),
			conf,
			approval(3, "r-1"),
			{
				...stale,
				record: { ...stale.record, registryVersion: 3 } as FlowRecord,
				over: { versions: { registry: { at: stale.record.acceptedAt + 10_000 } } },
			},
			codeBundle(5, "login", "r-4", "r-3"),
		]);
		expect(r.rulings.map(rowOf)).toEqual([
			"J12:unsupported",
			"J0:verified",
			"J13:verified",
			"J8:forged",
			"J7:forged",
		]);
	});

	it("C4: keeps a registration named `first` apart from the first key's own mark (Rules023e InsuffAt, ConfB)", () => {
		const key = firstKey(1);
		const first = { ...key, record: { ...key.record, id: "first" } as FlowRecord };
		const conf = {
			record: monitorRecord("confirmation", 2),
			preimage: {},
			over: { body: { v: 1, registration: "first" } },
		};
		const r = judged([first, conf, approval(3, "first")]);
		expect(r.rulings.map(rowOf)).toEqual(["J12:unsupported", "J0:verified", "J13:verified"]);
	});

	it("B4: does not count a refresh start naming the approval toward its one exchange (J2)", () => {
		const r = judged([
			firstKey(1),
			approval(2, "r-1"),
			refreshStart(3, "rf", "r-2"),
			codeStart(4, "login", "r-2"),
		]);
		expect(r.rulings.map(rowOf).slice(2)).toEqual(["J7:forged", "J12:unsupported"]);
	});

	it("refuses, as a TypeError, another writer's record whose body is missing or not its kind's (J0: what does not verify is not there)", () => {
		const reading = readingOf({ record: monitorRecord("denial", 3), preimage: {} }, empty);
		expect(() => judge({ ...reading, body: undefined })).toThrow(TypeError);
		expect(() => judge({ ...reading, body: { v: 1, key: "r-1" } })).toThrow(TypeError);
		expect(judge({ ...reading, body: { v: 1, registration: "r-1" } })).toMatchObject({ row: "J0" });
	});
});

describe("Outcome (§6.2)", () => {
	it("did not take for forged and held; for an acceptable verdict, by TimeOK; took for J0", () => {
		const step = approval(2, "r-1");
		const p = on([firstKey(1)]);
		const late = {
			...step,
			record: { ...step.record, acceptedAt: (authorization("sid-1").exp + 1) * 1000 },
		};
		expect(outcomeOf(readingOf(late, p), "unsupported")).toBe("didNotTake");
		expect(outcomeOf(readingOf(step, p), "unsupported")).toBe("took");
		expect(outcomeOf(readingOf(step, p), "forged")).toBe("didNotTake");
		expect(outcomeOf(readingOf(step, p), "held")).toBe("didNotTake");
		expect(ruled(late, p)).toMatchObject({
			row: "J12",
			entry: { judgment: { verdict: "unsupported", outcome: "didNotTake" } },
		});
		const conf = {
			...readingOf({ record: monitorRecord("confirmation", 2), preimage: {} }, p),
			body: { v: 1, registration: "r-1" },
		};
		expect(outcomeOf(conf, "verified")).toBe("took");
	});

	it("gives the entry the envelope, changes and parent the fold and the next records read", () => {
		const r = ruled(approval(2, "r-1"), on([firstKey(1)]));
		if ("wait" in r) throw new Error("waits");
		expect(r.entry.envelope).toEqual({
			id: "r-2",
			kind: "approval",
			op: "op-2",
			stage: 1,
			last: true,
			position: 2,
			acceptedAt: approval(2, "r-1").record.acceptedAt,
		});
		expect(r.entry.parent).toBe("r-1");
		expect(r.entry.changes.approval?.key).toBe("r-1");
		const bundle = ruled(
			refreshBundle(6, "rf-1", "r-5", "r-4"),
			on([...login(), refreshStart(5, "rf-1", "r-4")]),
		);
		expect(bundle).toMatchObject({ entry: { changes: { rotate: "r-4" } } });
		expect(
			ruled(codeStart(3, "login", "r-2"), on([firstKey(1), approval(2, "r-1")])),
		).toMatchObject({ entry: { parent: "r-2" } });
	});
});
