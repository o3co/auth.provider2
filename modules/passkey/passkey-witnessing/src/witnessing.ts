import { Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { PasskeyWitnessing } from "@mod/passkeys";

/** A mark or withdraw that finds a mark of a generation before again, once it removed one, removes it this often at most, then is unavailable. */
const tries = 3;

const tokenPattern = /^generation-(0|[1-9][0-9]*)$/;
/** The witness's token of a mark set for `generation`: the same for every mark of it. */
const tokenOf = (generation: number) => {
	if (!Number.isSafeInteger(generation) || generation < 0)
		throw new TypeError("passkey-witnessing: a key generation is a whole number at or above zero");
	return `generation-${generation}`;
};
/** The generation a mark was set for; a token of another form is unavailable, never a generation. */
const generationOf = (token: string) => {
	const generation = Number(tokenPattern.exec(token)?.[1]);
	if (!Number.isSafeInteger(generation)) throw new Unavailable("passkey-witnessing");
	return generation;
};

/** The witness's mark kept for key generations, over the one witness composed. */
export function witnessingOver(witness: PasskeyWitness): PasskeyWitnessing {
	return {
		marked: (subject) => witness.read(subject),
		// Ends with a mark of `generation` or a later set: one of a generation before is replaced.
		mark: async (subject, generation) => {
			const token = tokenOf(generation);
			for (let tried = 0; tried <= tries; tried++) {
				if (await witness.enroll(subject, token)) return;
				// Another's mark: read its token; one gone meanwhile is enrolled again.
				const held = await witness.markedWith(subject);
				if (held !== undefined && generationOf(held) >= generation) return;
				if (held !== undefined && tried < tries) await witness.withdraw(subject, held);
			}
			throw new Unavailable("passkey-witnessing");
		},
		withdraw: async (subject, generation) => {
			tokenOf(generation);
			for (let tried = 0; tried <= tries; tried++) {
				const token = await witness.markedWith(subject);
				if (token === undefined || generationOf(token) >= generation) return;
				// Removed only as that token's; read again, as a mark of a generation before may land meanwhile.
				if (tried < tries) await witness.withdraw(subject, token);
			}
			throw new Unavailable("passkey-witnessing");
		},
	};
}
