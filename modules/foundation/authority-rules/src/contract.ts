import { effectOf } from "./chain/chain.ts";
import { lifetimeMs, startOf, within } from "./client/client.ts";
import { contents } from "./evidence/evidence.ts";
import { changes, flowState } from "./fold/fold.ts";

/**
 * The transparency core's judgment rules, one library the Core's local check and the monitor both
 * run: Allowed, the one fold and stateOf, the verdict and the outcome. No I/O, clock, crypto or
 * state: a record's fields, its flow's judged prefix and the caller's verification functions in.
 */

export { type Allowance, type Ask, allowed, type Named, timely } from "./chain/chain.ts";
export type { ClientAt, ClientEvidence, StartOf } from "./client/client.ts";
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
	withoutRooted,
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

/**
 * A client's flow's: `start` (its evidence, a digest) → its op id (OpIdOf) and its elements (Elems),
 * or why not; `within` (its evidence, a time, a window) → whether its times hold it as TimeOK reads
 * them; `lifetimeMs`, the longest a client's own token lives from its start (15 minutes).
 */
export const clientRules = Object.freeze({ start: startOf, within, lifetimeMs });

/** The schemas the rules hold: a flow's state, a record's changes, and a Core writer's preimage content by kind. */
export const ruleSchemas = Object.freeze({ flowState, changes, contents });
