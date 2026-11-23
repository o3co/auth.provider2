import { schemas } from "@mod/transparency-wire";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
	type Changes,
	changes as changesSchema,
	type Envelope,
	emptyState,
	type Finding,
	type FlowEntry,
	type FlowState,
	flowState,
	fold,
	foldFlow,
} from "../fold.ts";

// Each case names the model definition it is taken from: kernel-spec §6.3 (Fold, Revoke, Abandon,
// NextGen, UpdRec), Rules023e.tla (Fold, Revoke, KeyFam), Step023.tla (Fold, AbnFam, StateOf) and
// RegAbandon023.tla (Eff).

const took: Finding = { verdict: "verified", outcome: "took" };
let at = 0;
const env = (kind: Envelope["kind"], over: Partial<Envelope> = {}): Envelope => {
	at += 1;
	return {
		id: `r-${at}`,
		kind,
		op: `op-${at}`,
		stage: 1,
		last: true,
		position: at,
		acceptedAt: 1000 * at,
		...over,
	};
};
const step = (s: FlowState, e: Envelope, c: Changes, j: Finding = took) => fold(s, e, c, j);
const firstKey = (s: FlowState, id: string) =>
	step(s, env("keyChange", { id }), { key: { credential: `c-${id}`, publicKey: `pk-${id}` } });
const login = (s: FlowState, key: string, approval: string, bundle: string) => {
	const a = step(s, env("approval", { id: approval }), {
		approval: { key, code: `code-${approval}`, client: "rp" },
		consume: [`statement:${approval}`],
	});
	return step(a, env("bundle", { id: bundle, stage: 2 }), {
		family: { approval },
		consume: [`code:${approval}`],
	});
};

describe("the one fold (kernel-spec §6.3 Fold)", () => {
	it("changes nothing unless the record is verified or unsupported and took (forged, held, didNotTake: Rules023e Fold `vd ∉ {ok, insuff}`, RegAbandon023 Eff)", () => {
		const s = firstKey(emptyState, "k1");
		const add = { key: { credential: "c2", publicKey: "pk2", by: "k1" } };
		for (const j of [
			{ verdict: "forged", outcome: "didNotTake" },
			{ verdict: "held", outcome: "didNotTake" },
			{ verdict: "verified", outcome: "didNotTake" },
			{ verdict: "unsupported", outcome: "didNotTake" },
		] as const)
			expect(step(s, env("keyChange"), add, j)).toBe(s);
		expect(Object.keys(step(s, env("keyChange", { id: "k2" }), add, took).keys)).toEqual([
			"k1",
			"k2",
		]);
		expect(
			Object.keys(
				step(s, env("keyChange", { id: "k3" }), add, { verdict: "unsupported", outcome: "took" })
					.keys,
			),
		).toContain("k3");
	});

	it("puts a first-trust key in with no chain, its position and time from the envelope (Rules023e Fold `ft`; UpdRec's roots from k)", () => {
		const e = env("keyChange", { id: "k1" });
		const s = step(emptyState, e, { key: { credential: "c1", publicKey: "pk1" } });
		expect(s.keys.k1).toEqual({
			credential: "c1",
			publicKey: "pk1",
			chain: [],
			position: e.position,
			acceptedAt: e.acceptedAt,
		});
	});

	it("adds a key, an approval or a family only while what it hangs from is live (Rules023e Fold `add`, `fam`: IF r.par ∈ S)", () => {
		expect(
			step(emptyState, env("keyChange"), { key: { credential: "c", publicKey: "p", by: "gone" } }),
		).toEqual(emptyState);
		expect(
			step(emptyState, env("approval"), { approval: { key: "gone", code: "x", client: "rp" } })
				.approvals,
		).toEqual({});
		expect(
			step(emptyState, env("bundle", { stage: 2 }), { family: { approval: "gone" } }).families,
		).toEqual({});
		const s = login(firstKey(emptyState, "k1"), "k1", "a1", "b1");
		expect(s.approvals.a1?.chain).toEqual(["k1"]);
		expect(s.families.b1).toMatchObject({
			approval: "a1",
			chain: ["k1"],
			client: "rp",
			rotation: 0,
		});
	});

	it("finds nothing by a name the state's records inherit, and names an item so as its own (C3: toString, __proto__, constructor)", () => {
		const s = firstKey(emptyState, "k1");
		for (const name of ["toString", "__proto__", "constructor"]) {
			expect(
				step(s, env("keyChange"), { key: { credential: "c", publicKey: "p", by: name } }),
			).toEqual(s);
			expect(
				step(s, env("approval"), { approval: { key: name, code: "x", client: "rp" } }),
			).toEqual(s);
			expect(step(s, env("bundle", { stage: 2 }), { family: { approval: name } })).toEqual(s);
			expect(step(s, env("bundle", { stage: 2 }), { rotate: name })).toEqual(s);
			expect(step(s, env("abandonment"), { abandon: name })).toEqual(s);
			const own = firstKey(emptyState, name);
			expect(Object.keys(own.keys)).toEqual([name]);
			expect(flowState.parse(own)).toEqual(own);
			expect(flowState.parse(JSON.parse(JSON.stringify(own)))).toEqual(own);
			const approved = step(own, env("approval", { id: "a1" }), {
				approval: { key: name, code: "x", client: "rp" },
			});
			expect(approved.approvals.a1?.chain).toEqual([name]);
		}
	});

	it("leaves the state as it is at a stage that is not the op's last, its changes aside (OI-03; Step023 Fold `sta`)", () => {
		const s = firstKey(emptyState, "k1");
		expect(
			step(s, env("start", { last: false }), { approval: { key: "k1", code: "c", client: "rp" } }),
		).toBe(s);
	});

	it("keeps the use-once marks the last stage sets, each once (UpdRec: 消費の印)", () => {
		const s = login(firstKey(emptyState, "k1"), "k1", "a1", "b1");
		expect(s.consumed).toEqual(["statement:a1", "code:a1"]);
		expect(step(s, env("bundle"), { consume: ["code:a1"] }).consumed).toEqual(s.consumed);
	});

	it("turns a live family's rotation on, and does nothing for a family not live (Step023 Fold `ref`: the family stays)", () => {
		const s = login(firstKey(emptyState, "k1"), "k1", "a1", "b1");
		const r = step(s, env("bundle", { stage: 2 }), { rotate: "b1" });
		expect(r.families.b1?.rotation).toBe(1);
		expect(r.families.b1?.acceptedAt).toBe(s.families.b1?.acceptedAt);
		expect(step(s, env("bundle"), { rotate: "nope" })).toEqual(s);
	});
});

describe("Revoke, Abandon and NextGen (kernel-spec §6.3)", () => {
	const chained = () => {
		let s = firstKey(emptyState, "k1");
		s = step(s, env("keyChange", { id: "k2" }), {
			key: { credential: "c2", publicKey: "pk2", by: "k1" },
		});
		s = login(s, "k2", "a1", "b1");
		s = firstKey(s, "other");
		return s;
	};

	it("takes the denied key and everything rooted at it: added keys, approvals, families (OI-24 DenyMode `desc`; the 0.22 letter `bothKeyFam` kept added keys)", () => {
		const s = step(chained(), env("denial"), { revoke: "k1" });
		expect(Object.keys(s.keys)).toEqual(["other"]);
		expect(s.approvals).toEqual({});
		expect(s.families).toEqual({});
	});

	it("takes the descendants of a denied key that is itself gone (Revoke: x 自身が削除ずみでも子孫は除く)", () => {
		const s = chained();
		const { k1: _gone, ...keys } = s.keys;
		const s2 = step({ ...s, keys }, env("denial"), { revoke: "k1" });
		expect(Object.keys(s2.keys)).toEqual(["other"]);
		expect(s2.families).toEqual({});
	});

	it("does nothing for a denial of a key not in the state (Revoke: 対象が無ければ何もしない)", () => {
		const s = chained();
		expect(step(s, env("denial"), { revoke: "none" })).toEqual(s);
	});

	it("takes a removed key and everything under it (UpdRec: 鍵の削除が成ったら、その鍵を根にする family も除く; Rules023 Fold `rev`: Under)", () => {
		const s = step(chained(), env("keyChange"), { removeKey: "k2" });
		expect(Object.keys(s.keys)).toEqual(["k1", "other"]);
		expect(s.families).toEqual({});
	});

	it("drops the abandoned op's family and keeps the marks; a family already gone is no change (Step023 Fold `abn`, W_RevBetween; OI-02)", () => {
		const s = chained();
		const a = step(s, env("abandonment"), { abandon: "b1" });
		expect(a.families).toEqual({});
		expect(a.consumed).toEqual(s.consumed);
		expect(step(a, env("abandonment"), { abandon: "b1" })).toEqual(a);
		expect(step(s, env("abandonment"), {})).toEqual(s);
	});

	it("moves the key generation on and drops every key, approval and family at an erasure boundary (Rules023e Fold `rst` -> {}; NextGen)", () => {
		const s = chained();
		const n = step(s, env("erasureBoundary"), {});
		expect(n).toEqual({ ...emptyState, keyGeneration: 1, consumed: s.consumed });
	});

	it("takes no reset through a record's changes while no rule allows a reset (its owner, a Core key change or a monitor's record, is open)", () => {
		expect(changesSchema.safeParse({ reset: true }).success).toBe(false);
	});

	it("leaves the state as it is at a confirmation and a tombstone (§6.3: 確認, 墓標 -> S)", () => {
		const s = chained();
		expect(step(s, env("confirmation"), {})).toBe(s);
		expect(step(s, env("tombstone"), {})).toBe(s);
	});
});

describe("foldFlow: stateOf over a flow (Step023 StateOf; transparency-wire's stateOf)", () => {
	const flow = { of: "subject", id: "sub-1" } as const;
	const entries = (): FlowEntry[] => {
		at = 0;
		const k = env("keyChange", { id: "k1" });
		const a = env("approval", { id: "a1" });
		const held = env("start", { id: "s1", last: false });
		return [
			{ envelope: k, changes: { key: { credential: "c1", publicKey: "pk1" } }, judgment: took },
			{
				envelope: a,
				changes: { approval: { key: "k1", code: "x", client: "rp" } },
				judgment: { verdict: "unsupported", outcome: "took" },
				parent: "k1",
			},
			{ envelope: held, changes: {}, judgment: { verdict: "held", outcome: "didNotTake" } },
		];
	};

	it("gives every position's result and the state the one fold makes, in transparency-wire's shape", () => {
		const s = foldFlow(flow, entries());
		expect(schemas.stateOf.safeParse(s).success).toBe(true);
		expect(s.position).toBe(3);
		expect(s.results.map((r) => [r.position, r.id, r.verdict, r.outcome])).toEqual([
			[1, "k1", "verified", "took"],
			[2, "a1", "unsupported", "took"],
			[3, "s1", "held", "didNotTake"],
		]);
		expect(flowState.parse(s.state)).toEqual(
			entries().reduce((x, e) => fold(x, e.envelope, e.changes, e.judgment), emptyState),
		);
		expect(foldFlow(flow, [])).toEqual({ v: 1, flow, position: 0, state: emptyState, results: [] });
	});

	it("reads a state's items from an object alone, refusing a list in its place", () => {
		const key = { credential: "c", publicKey: "p", chain: [], position: 1, acceptedAt: 0 };
		expect(flowState.safeParse({ ...emptyState, keys: [["k1", key]] }).success).toBe(false);
		expect(flowState.safeParse({ ...emptyState, keys: { k1: key } }).success).toBe(true);
		expect(flowState.safeParse({ ...emptyState, keys: { k1: { ...key, extra: 1 } } }).success).toBe(
			false,
		);
	});

	it("refuses entries that are not the flow's positions from 1 in order (StateOf is defined over the whole prefix)", () => {
		const [first, second] = entries();
		expect(() => foldFlow(flow, [second as FlowEntry])).toThrow(TypeError);
		expect(() => foldFlow(flow, [first as FlowEntry, first as FlowEntry])).toThrow(TypeError);
	});

	it("steps one record at a time to stateOf at every position, and the state stays in its schema (Step023 KP_06, NoSkip)", () => {
		const kinds = [
			"keyChange",
			"approval",
			"start",
			"bundle",
			"denial",
			"abandonment",
			"erasureBoundary",
			"confirmation",
		] as const;
		const ref = fc.constantFrom("r-1", "r-2", "r-3", "r-4", "r-5", "r-6");
		const changesArb: fc.Arbitrary<Changes> = fc.record(
			{
				key: fc.record(
					{ credential: fc.constant("c"), publicKey: fc.constant("p"), by: ref },
					{
						requiredKeys: ["credential", "publicKey"],
					},
				),
				removeKey: ref,
				approval: fc.record({ key: ref, code: fc.constant("x"), client: fc.constant("rp") }),
				family: fc.record({ approval: ref }),
				rotate: ref,
				consume: fc.array(fc.constantFrom("m1", "m2"), { maxLength: 2 }),
				revoke: ref,
				abandon: ref,
			},
			{ requiredKeys: [] },
		);
		const judged = fc.constantFrom<Finding>(
			took,
			{ verdict: "unsupported", outcome: "took" },
			{ verdict: "held", outcome: "didNotTake" },
			{ verdict: "forged", outcome: "didNotTake" },
		);
		const entry = fc.tuple(fc.constantFrom(...kinds), fc.boolean(), changesArb, judged);
		fc.assert(
			fc.property(fc.array(entry, { maxLength: 6 }), (list) => {
				const es: FlowEntry[] = list.map(([kind, last, changes, judgment], i) => ({
					envelope: {
						id: `r-${i + 1}`,
						kind,
						op: `op-${i + 1}`,
						stage: last ? 2 : 1,
						last,
						position: i + 1,
						acceptedAt: i,
					},
					changes,
					judgment,
				}));
				let s = emptyState;
				es.forEach((e, i) => {
					s = fold(s, e.envelope, e.changes, e.judgment);
					expect(flowState.parse(s)).toEqual(s);
					expect(foldFlow(flow, es.slice(0, i + 1)).state).toEqual(s);
				});
			}),
		);
	});
});
