import { Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { PasskeyWitnessing } from "@mod/passkeys";

/** A withdraw that finds a mark of a generation before again, once it removed one, removes it this often at most, then is unavailable. */
const withdrawTries = 3;

const tokenPattern = /^generation-(0|[1-9][0-9]*)$/;
/** The witness's token of a mark set for `generation`: the same for every mark of it. */
const tokenOf = (generation: number) => {
	if (!Number.isSafeInteger(generation) || generation < 0)
		throw new TypeError("passkey-witnessing: a key generation is a whole number at or above zero");
	return `generation-${generation}`;
};
/** The generation a mark was set for; a token of another form is unavailable, never a generation. */
const generationOf = (token: string) => {
	const read = tokenPattern.exec(token);
	if (!read) throw new Unavailable("passkey-witnessing");
	return Number(read[1]);
};

/** The witness's mark kept for key generations, over the one witness composed. */
export function witnessingOver(witness: PasskeyWitness): PasskeyWitnessing {
	return {
		marked: (subject) => witness.read(subject),
		mark: async (subject, generation) => {
			// Set unless a mark is: whichever generation set it, the subject carries one.
			await witness.enroll(subject, tokenOf(generation));
		},
		withdraw: async (subject, generation) => {
			tokenOf(generation);
			for (let tries = 0; tries <= withdrawTries; tries++) {
				const token = await witness.markedWith(subject);
				if (token === undefined || generationOf(token) >= generation) return;
				// Removed only as that token's; read again, as a mark of a generation before may land meanwhile.
				if (tries < withdrawTries) await witness.withdraw(subject, token);
			}
			throw new Unavailable("passkey-witnessing");
		},
	};
}
