import { z } from "zod";

/**
 * The words of a reset (V22): the instruction an embedder's recovery service signs to send a subject
 * back to the first key's path, the window it is taken in, the faults a reset is found with, and the
 * answers of a reset not placed. The log's words for it (the `typ`s, the boundary record's kind and
 * body, the op id, the signer set's count) are the transparency log's contract, not this one.
 */

const v = z.literal(1);
const count = z.number().int().nonnegative();
const id = z.string().min(1);

/** The longest an instruction lives, `exp` past `iat`, in seconds. */
export const resetLifetime = 600;
/** How far an embedder's clock may stray, in seconds: a reset is taken from `iat` less it to `exp` plus it. */
export const instructionSkew = 60;

/**
 * Why a reset does not take, in the order the rule checks them: `shape` (the instruction does not read
 * as one), `set` (no signer set of the boundary's version), `signature` (no key of that set verifies
 * it, or another `typ`), `installation`, `subject` (another than the flow's), `op` (not
 * `reset:` and its id), `generation` (its `kg` is not the key generation before its position) and
 * `time` (accepted outside its window). The first six are forged; the last two befall an honest
 * monitor too, and the reset is verified but does not take.
 */
export const resetFaults = Object.freeze([
	"shape",
	"set",
	"signature",
	"installation",
	"subject",
	"op",
	"generation",
	"time",
] as const);
export type ResetFault = (typeof resetFaults)[number];

/**
 * The instruction's payload, signed by the embedder's recovery service as `reset-instruction+jwt`:
 * this installation, the subject, the action, the key generation it was signed at (`kg`), a random id
 * of 128 bits or more (22 to 43 base64url characters, a nonce too), and its issue and expiry times in
 * seconds, living `resetLifetime` at most.
 */
export const resetInstruction = z
	.object({
		v,
		installation: id,
		subject: id,
		action: z.literal("reset"),
		kg: count,
		id: z.string().regex(/^[A-Za-z0-9_-]{22,43}$/),
		iat: count,
		exp: count,
	})
	.strict()
	.refine((i) => i.iat < i.exp && i.exp - i.iat <= resetLifetime, {
		message: `an instruction is issued before it expires, living ${resetLifetime} s at most`,
	});
export type ResetInstruction = z.infer<typeof resetInstruction>;

const invalid = z.object({ v, result: z.literal("invalid"), fault: z.enum(resetFaults) }).strict();
const conflict = z.object({ v, result: z.literal("conflict") }).strict();

/**
 * A reset not placed, as its placer answers: `invalid` with its fault, or `conflict` where the same id
 * was placed with another instruction. A placed reset is answered as the log answers an append.
 * `schema` reads one; `invalid` and `conflict` make one.
 */
export const resetRefusal = Object.freeze({
	schema: z.union([invalid, conflict]),
	invalid: (fault: ResetFault): z.infer<typeof invalid> => ({ v: 1, result: "invalid", fault }),
	conflict: (): z.infer<typeof conflict> => ({ v: 1, result: "conflict" }),
});
export type ResetRefusal = z.infer<typeof resetRefusal.schema>;
