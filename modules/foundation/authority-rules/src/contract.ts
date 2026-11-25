import { bundleEffect, effectOf } from "./chain/chain.ts";
import { lifetimeMs, startOf, within } from "./client/client.ts";
import { contents } from "./evidence/evidence.ts";
import { changes, flowState } from "./fold/fold.ts";
import { cHash } from "./id-token/id-token.ts";

/**
 * The transparency core's judgment rules, one library the Core's local check and the monitor both
 * run: Allowed, the one fold, the verdict and the outcome. No I/O, clock, crypto or state: a
 * record's fields, its flow's judged prefix and the caller's verification functions in.
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
	type RecordKind,
} from "./fold/fold.ts";
export {
	type FlowRecord,
	judge,
	type Opening,
	type Reading,
	type Row,
	type Ruling,
	type Window,
} from "./judgment/judgment.ts";
export { type ResetContext, type ResetFinding, resetFinding } from "./reset/reset.ts";
export { effectOf };

/**
 * The rules by kind of token, as the Core derives what they check:
 * - `client`, a client's own flow's: `start` (its evidence, a digest) → its op id (OpIdOf) and its
 *   elements (Elems), or why not; `within` (its evidence, a time, a window) → whether its times hold
 *   it as TimeOK reads them; `lifetimeMs`, the longest its token lives from its start (15 minutes).
 * - `idToken`: `cHash` (a code's SHA-256 digest) → its `c_hash`, the left half (A21).
 * - `bundle`: `effect` (its `via`, root and tokens' frames) → its changes, Eff of its record, which the
 *   Core's intent takes as is.
 */
export const tokenRules = Object.freeze({
	client: Object.freeze({ start: startOf, within, lifetimeMs }),
	idToken: Object.freeze({ cHash }),
	bundle: Object.freeze({ effect: bundleEffect }),
});

/** The schemas the rules hold: a flow's state, a record's changes, and a Core writer's preimage content by kind. */
export const ruleSchemas = Object.freeze({ flowState, changes, contents });
