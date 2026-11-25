import { schemas } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	allowed,
	effectOf,
	emptyState,
	type FlowEntry,
	type FlowRecord,
	type FlowState,
	fold,
	foldFlow,
	judge,
	ruleSchemas,
} from "../src/contract.ts";
import {
	added,
	addedKey,
	addParts,
	approval,
	codeBundle,
	codeStart,
	deletion,
	firstKey,
	newKey,
	refreshBundle,
	refreshStart,
	type Step,
} from "./fixtures/flow.ts";
import {
	checks,
	context,
	coreRecord,
	coseKey,
	monitorRecord,
	preimage,
	subject,
} from "./fixtures/world.ts";

/** An honest Core's flow: each record checked by Allowed before its append, then judged and folded. */
function run(steps: readonly (Step | { record: FlowRecord; body: unknown })[]) {
	let state: FlowState = emptyState;
	const prior: FlowEntry[] = [];
	const rows: string[] = [];
	for (const step of steps) {
		const shared = { state, prior, checks, context: context() };
		if ("preimage" in step) {
			const ask = { ...shared, record: step.record, preimage: step.preimage };
			expect(allowed(ask)).toEqual({ allowed: true });
			const intent = effectOf(ask);
			const ruling = judge({
				...shared,
				record: step.record,
				opening: { opened: step.preimage },
				keySets: { ever: ["mk-1"], atRecord: ["mk-1"] },
			});
			if ("wait" in ruling) throw new Error("waits");
			expect(ruling.entry.changes).toEqual(intent);
			rows.push(`${ruling.row}:${ruling.entry.judgment.verdict}`);
			prior.push(ruling.entry);
		} else {
			const ruling = judge({ ...shared, record: step.record, body: step.body });
			if ("wait" in ruling) throw new Error("waits");
			rows.push(`${ruling.row}:${ruling.entry.judgment.verdict}`);
			prior.push(ruling.entry);
		}
		const last = prior[prior.length - 1] as FlowEntry;
		state = fold(state, last.envelope, last.changes, last.judgment);
	}
	return { state, prior, rows };
}

describe("an honest flow through the contract (KP-04, Step023 CoreMonAgree, KP_06)", () => {
	const steps = [
		firstKey(1),
		approval(2, "r-1"),
		codeStart(3, "login", "r-2"),
		codeBundle(4, "login", "r-3", "r-2"),
		{ record: monitorRecord("confirmation", 5), body: { v: 1, registration: "r-1" } },
		refreshStart(6, "rf-1", "r-4"),
		refreshBundle(7, "rf-1", "r-6", "r-4"),
		{
			record: coreRecord("abandonment", 8, {
				op: "abandonment:1:rf-1",
				abandons: { op: "rf-1", attempt: 1, digest: "p".repeat(43) },
			}),
			preimage: preimage({}),
		},
	];

	it("is allowed by the Core's check before each append, never forged, and the Core's intent is the monitor's Eff(r)", () => {
		const { rows } = run(steps);
		expect(rows).toEqual([
			"J12:unsupported",
			"J12:unsupported",
			"J12:unsupported",
			"J12:unsupported",
			"J0:verified",
			"J13:verified",
			"J13:verified",
			"J13:verified",
		]);
	});

	it("folds to the stateOf the monitor signs, in transparency-wire's shape and these rules' state schema", () => {
		const { state, prior } = run(steps);
		const s = foldFlow(subject, prior);
		expect(schemas.stateOf.safeParse(s).success).toBe(true);
		expect(ruleSchemas.flowState.parse(s.state)).toEqual(state);
		expect(Object.keys(state.keys)).toEqual(["r-1"]);
		expect(state.families).toEqual({});
		expect(state.consumed).toEqual(["statement:sid-1", "code:r-2"]);
		for (const e of prior) expect(ruleSchemas.changes.parse(e.changes)).toEqual(e.changes);
	});
});

describe("an honest passkey-add through the contract (proposal 3.13, P 356)", () => {
	const third = { credential: "cred-3A", publicKey: coseKey(3) };
	const steps = [
		firstKey(1),
		added(2, "r-1"),
		{ record: monitorRecord("confirmation", 3), body: { v: 1, registration: "r-1" } },
		added(4, "r-2", addParts("add-2", third, addedKey)),
	];

	it("judges an added key as its approving key's root: unsupported before its confirmation, verified after", () => {
		const { rows, state } = run(steps);
		expect(rows).toEqual(["J12:unsupported", "J12:unsupported", "J0:verified", "J13:verified"]);
		expect(Object.keys(state.keys)).toEqual(["r-1", "r-2", "r-4"]);
		expect(state.consumed).toEqual(["statement:add-1", "statement:add-2"]);
	});
});

describe("an honest deletion through the contract (V24, Rules023del)", () => {
	const third = { credential: "cred-3A", publicKey: coseKey(3) };
	const steps = [
		firstKey(1),
		added(2, "r-1"),
		deletion(3, "r-1", addedKey.credential),
		{ record: monitorRecord("confirmation", 4), body: { v: 1, registration: "r-1" } },
		added(5, "r-1", addParts("add-2", third, newKey)),
		deletion(6, "r-1", third.credential, newKey, { sid: "del-2" }),
	];

	it("judges a deletion as its approving key's root: unsupported before its confirmation, verified after", () => {
		const { rows, state } = run(steps);
		expect(rows).toEqual([
			"J12:unsupported",
			"J12:unsupported",
			"J12:unsupported",
			"J0:verified",
			"J13:verified",
			"J13:verified",
		]);
		expect(Object.keys(state.keys)).toEqual(["r-1"]);
		expect(state.consumed).toEqual([
			"statement:add-1",
			"statement:del-1",
			"statement:add-2",
			"statement:del-2",
		]);
	});
});
