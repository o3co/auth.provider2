import { z } from "zod";
import { base64url, count, flow, id, ordinal, v } from "../records/records.ts";
import { unique } from "../text/text.ts";

/** The monitor's four verdicts (A45) and the outcome, a separate axis: whether a stage took effect. */
export const judgments = Object.freeze({
	verdicts: Object.freeze(["verified", "forged", "held", "unsupported"] as const),
	outcomes: Object.freeze(["took", "didNotTake"] as const),
});

/** A shard's generation state, and why an id is not accepted (for operators alone). */
export const statusWords = Object.freeze({
	shardStates: Object.freeze(["running", "stopped"] as const),
	denyReasons: Object.freeze([
		"forged",
		"held",
		"generationStopped",
		"bundleAbandoned",
		"rootDenied",
	] as const),
});

/** Room the later stages add to, signed with the rest; a reader ignores a name in it it does not know. */
const ext = z.record(z.string(), z.unknown()).optional();
const verdict = z.enum(judgments.verdicts);
const outcome = z.enum(judgments.outcomes);
const ids = z
	.array(id)
	.refine((list) => unique(list, (x) => x), { message: "an id is named twice" });

export const judgment = z
	.object({ v, id, flow, position: ordinal, shard: id, n: ordinal, verdict, outcome })
	.strict();

export const checkpoint = z
	.object({
		v,
		shard: id,
		watermark: count,
		deny: ids,
		/** The ids marked to count toward a writer's hold limit (A46). */
		counted: ids,
		/** The forged ids (each one the monitor's signed judgment says `forged`), each with its writer's generation: the generations the log stops on accepting this. */
		forged: z
			.array(z.object({ id, generation: ordinal }).strict())
			.refine((list) => unique(list, (f) => f.id), { message: "an id is named twice" }),
		ext,
	})
	.strict()
	.refine((c) => c.forged.every((f) => c.deny.includes(f.id)), {
		message: "a forged id is among the not-accepted ids",
	});

const shardState = z
	.object({ watermark: count, generation: ordinal, state: z.enum(statusWords.shardStates) })
	.strict();
export const status = z
	.object({ v, version: ordinal, shards: z.record(id, shardState), deny: ids, ext })
	.strict();
export const statusReasons = z
	.object({
		v,
		version: ordinal,
		reasons: z
			.array(z.object({ id, reason: z.enum(statusWords.denyReasons) }).strict())
			.refine((list) => unique(list, (r) => r.id), { message: "an id is named twice" }),
	})
	.strict();

export const stateOf = z
	.object({
		v,
		flow,
		position: count,
		/** The flow's state as the one fold makes it, held to `authority-rules`' schema, not here. */
		state: z.record(z.string(), z.unknown()),
		/** Each position's verdict and outcome, from 1 to `position`, each once and in order. */
		results: z.array(z.object({ position: ordinal, id, verdict, outcome }).strict()),
	})
	.strict()
	.refine(
		(s) => s.results.length === s.position && s.results.every((r, i) => r.position === i + 1),
		{ message: "results go from 1 to the position" },
	);

/**
 * An object a signer set signs (a status, a checkpoint, a stateOf: KA-18), as RFC 7515's JWS JSON
 * General Serialization: one payload and a signature per signer. Each protected header names `alg`,
 * the object's `typ` and its key's `kid`; a reader verifies each signature with the set's key of that
 * kid and counts the kids that verify against the set's `required`.
 */
export const setSigned = z
	.object({
		payload: base64url,
		signatures: z
			.array(z.object({ protected: base64url, signature: base64url }).strict())
			.min(1)
			.refine((list) => unique(list, (s) => s.protected), {
				message: "a protected header is named twice",
			}),
	})
	.strict();

export type Judgment = z.infer<typeof judgment>;
export type Checkpoint = z.infer<typeof checkpoint>;
export type Status = z.infer<typeof status>;
export type StateOf = z.infer<typeof stateOf>;
export type Verdict = z.infer<typeof verdict>;
export type StageOutcome = z.infer<typeof outcome>;
