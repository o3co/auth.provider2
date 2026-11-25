import { z } from "zod";

/**
 * A subject flow's applied state as a receiver reads it: the parts of the state a log's signer set
 * signs in a stateOf that a receiver may rest on, in this wire's words. The state's other parts are
 * not read here: whoever makes the state keeps them, and holds its state to give these reads.
 *
 * The parts read, as the state's JSON names them: `keyGeneration` (the subject's key generation, a
 * whole number from 0) and `keys` (a plain object, one own entry for each key the state holds at its
 * position, its value naming the key's credential id as `credential`, in canonical base64url). Each
 * entry is read by its own key, so an entry the log named `__proto__` is one entry too.
 */

const sextets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** Base64url without padding, in its one spelling: a length one bytes give, the last character's unused bits zero. */
const canonical = (text: string) => {
	const rest = text.length % 4;
	if (!/^[A-Za-z0-9_-]+$/.test(text) || rest === 1) return false;
	const last = sextets.indexOf(text.charAt(text.length - 1));
	return rest === 0 || last % (rest === 2 ? 16 : 4) === 0;
};
const credential = z.string().refine(canonical);
const keyGeneration = z.number().int().nonnegative();

/** A plain object, as JSON gives one: its prototype Object's or none. */
const isPlain = (value: unknown): value is Record<string, unknown> => {
	if (value === null || typeof value !== "object") return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/**
 * The credential ids of the keys a subject flow's state holds, each once, as a set (no order
 * promised); none where the state does not read so (not a plain object, no `keys` plain object, or
 * an entry naming no credential id in canonical base64url). An empty list is a state that holds no
 * key: a reader tells it from none.
 */
export function credentialsOf(state: unknown): readonly string[] | undefined {
	if (!isPlain(state) || !Object.hasOwn(state, "keys")) return undefined;
	const keys = state.keys;
	if (!isPlain(keys)) return undefined;
	const ids: string[] = [];
	for (const [, entry] of Object.entries(keys)) {
		// The entry's own `credential` alone: one it inherits is none.
		if (!isPlain(entry) || !Object.hasOwn(entry, "credential")) return undefined;
		const read = credential.safeParse(entry.credential);
		if (!read.success) return undefined;
		if (!ids.includes(read.data)) ids.push(read.data);
	}
	return Object.freeze(ids);
}

/** A subject flow's key generation: the resets and erasures that took (0 for a JSON `-0`); none where the state does not read so. */
export function keyGenerationOf(state: unknown): number | undefined {
	if (!isPlain(state) || !Object.hasOwn(state, "keyGeneration")) return undefined;
	const read = keyGeneration.safeParse(state.keyGeneration);
	return read.success ? read.data + 0 : undefined;
}
