import type { PasskeyGenerations, Passkeys } from "@mod/passkeys";
import { resetInstruction } from "@mod/reset-wire";
import type { Transparency } from "@mod/transparency";
import type { PasskeyReset } from "./contract.ts";

/** The instruction's subject, read from its payload unverified: the log verified it before placing. */
function subjectOf(instruction: string): string | undefined {
	try {
		const payload = JSON.parse(
			Buffer.from(instruction.split(".")[1] ?? "", "base64url").toString(),
		) as unknown;
		const read = resetInstruction.safeParse(payload);
		return read.success ? read.data.subject : undefined;
	} catch {
		return undefined;
	}
}

/**
 * The reset's path over the Core's transparency and passkeys: the instruction handed to the log; a
 * placed one's subject's flow tended, so the boundary is taken in, and its passkeys settled.
 */
export function resetOver(p: {
	readonly transparency: Transparency;
	readonly passkeys: Passkeys;
	readonly generations: PasskeyGenerations;
}): PasskeyReset {
	return {
		async reset(instruction) {
			const { answer } = await p.transparency.reset({ instruction });
			if (answer.result !== "accepted") return answer;
			// Placed, so the log read its shape: one it could not read is no state to pass by.
			const subject = subjectOf(instruction);
			if (subject === undefined)
				throw new TypeError("passkey-reset: a placed instruction names no subject");
			await p.transparency.tend({ of: "subject", id: subject });
			await p.passkeys.settle(subject);
			return answer;
		},
		// The applied state lags the log until a boundary is taken in: tended first, so a reset placed
		// or an erasure on the log is counted.
		async generation(subject) {
			const tended = await p.transparency.tend({ of: "subject", id: subject });
			// A boundary taken in drops keys: settled as any tend that stepped is.
			if (!("refused" in tended) && tended.stepped > 0) await p.passkeys.settle(subject);
			return p.generations.generation(subject);
		},
	};
}
