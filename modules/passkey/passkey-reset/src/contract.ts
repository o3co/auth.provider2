import { contract } from "@mod/kernel";
import { stances } from "@mod/promises";
import type { ResetAnswer } from "@mod/transparency";

/**
 * The reset's path in the Core (V22 §B.6), the one way a subject's last key goes: an embedder's
 * recovery procedure hands it a reset instruction its recovery service signed, Core-side alone,
 * never reached from the Front.
 */
export interface PasskeyReset {
	/**
	 * Hands the instruction to the log (on L0 the log in the Core places it as the monitor does) and
	 * answers the log's answer; where placed, it tends the subject's flow and settles its passkeys
	 * first.
	 */
	reset(instruction: string): Promise<ResetAnswer>;
	/**
	 * The subject's key generation, as the Core's applied state holds it once the subject's flow is
	 * tended: the instruction's `kg` on L0's path. L1's procedure reads the monitor's signed `stateOf`
	 * instead, never this.
	 */
	generation(subject: string): Promise<number>;
}

/** Taken only by a module that declares where it stands on the promises (O1): the reset's path is a power. */
export const passkeyReset = contract<PasskeyReset>("passkey-reset", {
	takersContribute: stances,
});
