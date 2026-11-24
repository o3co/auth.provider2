import { instructionSkew, type ResetFault, resetInstruction } from "@mod/reset-wire";
import {
	logTyps,
	opIds,
	type StageOutcome,
	schemas,
	tokens,
	type Verdict,
} from "@mod/transparency-wire";
import type { Checks, Context } from "../evidence/evidence.ts";
import type { FlowState } from "../fold/fold.ts";

/** What a reset is found against beside its flow: the installation, and the reset instruction's signer set of each version. */
export interface ResetContext {
	readonly installation: string;
	/**
	 * The reset instruction's signer set of a version, its public keys; `absent` where the
	 * publisher's flow, read to its end, holds no set of that version; none where it is not yet read.
	 */
	readonly sets: (version: number) => readonly unknown[] | "absent" | undefined;
}

/** A reset's finding (J0r, §6.2): its verdict and outcome, and the fault that stops it, where one does. */
export interface ResetFinding {
	readonly verdict: Verdict;
	readonly outcome: StageOutcome;
	readonly reason?: ResetFault;
}

const forged = (reason: ResetFault): ResetFinding => ({
	verdict: "forged",
	outcome: "didNotTake",
	reason,
});
const missed = (reason: ResetFault): ResetFinding => ({
	verdict: "verified",
	outcome: "didNotTake",
	reason,
});

/** The instruction's payload, read unverified: its shape is a fault of its own, before its signature. */
function payloadOf(instruction: string): unknown {
	const part = instruction.split(".")[1] ?? "";
	const bytes = Buffer.from(part, "base64url");
	// As the log reads it: base64url in its one spelling, strict UTF-8, a key named once.
	if (bytes.toString("base64url") !== part) return undefined;
	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return undefined;
	}
	const read = tokens.parse(text);
	return "value" in read ? read.value : undefined;
}

/**
 * A reset boundary's finding, by its body (as its envelope's), its flow's state before it, the
 * caller's verification and its acceptance time (ms). The faults in `resetFaults`' order, the first
 * that holds named: `shape` to `op` forged; `generation` and `time` verified but not taking. A signer
 * set version not yet read holds it; the monitor runs this before it places a reset, and the judgment
 * runs it again.
 */
export function resetFinding(
	body: unknown,
	state: FlowState,
	checks: Checks,
	context: Context,
	acceptedAt: number,
): ResetFinding {
	const reset = context.reset;
	const boundary = schemas.bodies.resetBoundary.safeParse(body);
	if (!boundary.success) return forged("shape");
	const { flow, op, set, instruction } = boundary.data;
	const read = resetInstruction.safeParse(payloadOf(instruction));
	if (!read.success) return forged("shape");
	const keys = reset?.sets(set);
	if (keys === undefined) return { verdict: "held", outcome: "didNotTake" };
	if (keys === "absent") return forged("set");
	const verified = checks.verifyJws(instruction, keys);
	const typ = (verified?.header as { typ?: unknown } | undefined)?.typ;
	if (!verified || typ !== logTyps.resetInstruction) return forged("signature");
	const i = read.data;
	if (i.installation !== reset?.installation) return forged("installation");
	if (flow.of !== "subject" || flow.id !== i.subject) return forged("subject");
	if (op !== opIds.reset(i.id)) return forged("op");
	if (i.kg !== state.keyGeneration) return missed("generation");
	const skew = instructionSkew * 1000;
	if (acceptedAt < i.iat * 1000 - skew || acceptedAt > i.exp * 1000 + skew) return missed("time");
	return { verdict: "verified", outcome: "took" };
}
