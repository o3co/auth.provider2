import { z } from "zod";

/**
 * A flow's applied state as a receiver reads it: the parts of the state a log's signer set signs in
 * a stateOf that a receiver may rest on, in this wire's words. The state's other parts are not read
 * here: whoever folds the state keeps them, and holds its state to give these reads.
 *
 * The parts read, as the state's JSON names them: `keyGeneration` (the subject's key generation, a
 * whole number from 0) and `keys` (an object, one own entry for each live key, its value naming the
 * key's credential id as `credential`). Each entry is read by its own key, so an entry the log named
 * `__proto__` is one entry too.
 */

const credential = z.string().min(1);
const keyEntry = z.looseObject({ credential });
const keyGeneration = z.number().int().nonnegative();

const isObject = (value: unknown): value is Record<string, unknown> =>
	value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * The credential ids of the keys a subject flow's state holds, each live key's once, in the state's
 * order; none where the state does not read so (not an object, no `keys` object, or an entry naming
 * no credential id). An empty list is a state that holds no key: a reader tells it from none.
 */
export function credentialsOf(state: unknown): readonly string[] | undefined {
	if (!isObject(state) || !Object.hasOwn(state, "keys")) return undefined;
	const keys = state.keys;
	if (!isObject(keys)) return undefined;
	const ids: string[] = [];
	for (const [, entry] of Object.entries(keys)) {
		const read = keyEntry.safeParse(entry);
		if (!read.success) return undefined;
		if (!ids.includes(read.data.credential)) ids.push(read.data.credential);
	}
	return Object.freeze(ids);
}

/** A subject flow's key generation: the resets and erasures that took; none where the state does not read so. */
export function keyGenerationOf(state: unknown): number | undefined {
	if (!isObject(state) || !Object.hasOwn(state, "keyGeneration")) return undefined;
	const read = keyGeneration.safeParse(state.keyGeneration);
	return read.success ? read.data : undefined;
}
