import { Unavailable } from "@mod/kernel";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { LocalMarks } from "./records/records.ts";

/** An enroll that finds a mark gone before it reads its token sets it again this often, then is unavailable. */
const enrollTries = 3;

/** The passkey witness over its marks, in the store beside the passkeys. */
export function localWitness(marks: LocalMarks): PasskeyWitness {
	return {
		read: async (subject) => (await marks.read(subject)) !== undefined,
		markedWith: async (subject) => (await marks.read(subject))?.token,
		enroll: async (subject, token) => {
			for (let tries = 0; tries < enrollTries; tries++) {
				const set = await marks.set(subject, token);
				if (set === "created") return true;
				// No mark is set past the subject's erasure.
				if (set === "erased") break;
				// The mark found, read after: answered by its token, unless withdrawn between.
				const held = await marks.read(subject);
				if (held !== undefined) return held.token === token;
			}
			throw new Unavailable("users-local");
		},
		withdraw: (subject, token) => marks.remove(subject, token),
	};
}
