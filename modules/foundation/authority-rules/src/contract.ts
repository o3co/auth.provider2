import { effectOf } from "./chain/chain.ts";
import { contents } from "./evidence/evidence.ts";
import { changes, flowState } from "./fold/fold.ts";

/**
 * The transparency core's judgment rules, one library the Core's local check and the monitor both
 * run: Allowed, the one fold and stateOf, the verdict and the outcome. No I/O, clock, crypto or
 * state: a record's fields, its flow's judged prefix and the caller's verification functions in.
 */

export { type Allowance, type Ask, allowed, type Named, timely } from "./chain/chain.ts";
export type { Checks, Context, RuleTimes } from "./evidence/evidence.ts";
export {
	abandonedFamily,
	type Changes,
	type Envelope,
	emptyState,
	type Finding,
	type FlowEntry,
	type FlowState,
	fold,
	foldFlow,
	type RecordKind,
} from "./fold/fold.ts";
export {
	type FlowRecord,
	judge,
	type Opening,
	outcomeOf,
	type Reading,
	type Row,
	type Ruling,
	type Window,
} from "./judgment/judgment.ts";
export { effectOf };

/** The schemas the rules hold: a flow's state, a record's changes, and a Core writer's preimage content by kind. */
export const ruleSchemas = Object.freeze({ flowState, changes, contents });
