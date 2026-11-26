import { credentialsOf, keyGenerationOf } from "@mod/flow-state-wire";
import { describe, expect, it } from "vitest";
import {
	type Changes,
	type Envelope,
	emptyState,
	type FlowState,
	flowState,
	fold,
} from "../fold.ts";

// flow-state-wire holds how a receiver reads a flow's applied state (a stateOf's `state`); the fold
// makes that state, so it holds its state to give those reads, as a stateOf carries it (JSON).

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
const step = (s: FlowState, e: Envelope, c: Changes) =>
	fold(s, e, c, { verdict: "verified", outcome: "took" });
const added = (s: FlowState, id: string, credential: string, by?: string) =>
	step(s, env("keyChange", { id }), {
		key: { credential, publicKey: `pk-${id}`, ...(by === undefined ? {} : { by }) },
	});
/** The state as a stateOf carries it: its JSON, read back. */
const carried = (s: FlowState): unknown => JSON.parse(JSON.stringify(s));

describe("the fold's state, read as flow-state-wire reads it", () => {
	it("gives the credential ids of its live keys and its key generation", () => {
		expect(credentialsOf(carried(emptyState))).toEqual([]);
		expect(keyGenerationOf(carried(emptyState))).toBe(0);
		const two = added(added(emptyState, "k1", "AQID"), "k2", "BAUG", "k1");
		expect(credentialsOf(carried(two))).toEqual(["AQID", "BAUG"]);
		expect(flowState.parse(carried(two))).toEqual(two);
	});

	it("drops a removed key's credential, and every key's at an erasure boundary, the generation one on", () => {
		const two = added(added(emptyState, "k1", "AQID"), "k2", "BAUG", "k1");
		expect(credentialsOf(carried(step(two, env("keyChange"), { removeKey: "k2" })))).toEqual([
			"AQID",
		]);
		const erased = step(two, env("erasureBoundary"), {});
		expect(credentialsOf(carried(erased))).toEqual([]);
		expect(keyGenerationOf(carried(erased))).toBe(1);
	});

	it("carries a state naming an item __proto__, which no record id is, as one a receiver reads as none", () => {
		const state = carried(added(emptyState, "__proto__", "AQID"));
		expect(credentialsOf(state)).toBeUndefined();
	});
});
