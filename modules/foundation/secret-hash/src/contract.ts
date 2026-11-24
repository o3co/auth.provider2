import { contract } from "@mod/kernel";
import { readHash, readWork } from "./hashes.ts";

declare const madeByRead: unique symbol;
/** A stored hash, made only by `readSecretHash`; `work` names what checking against it costs, alike for equal work. */
export interface SecretHash {
	readonly work: string;
	readonly [madeByRead]: true;
}

declare const madeByWork: unique symbol;
/** A work named without a hash of it, made only by `readSecretWork`: what a checker makes decoys of, never a hash checked. */
export interface SecretWork {
	readonly work: string;
	readonly [madeByWork]: true;
}

export interface SecretChecker {
	/**
	 * Whether the secret matches the hash. Every call computes once per kind of work in use, a decoy
	 * for each kind but the hash's, so a call without a hash takes the same work as one with it.
	 * Rejects as unavailable, before any computation, while its assembly runs its limit of checks.
	 */
	check(hash: SecretHash | undefined, secret: string): Promise<boolean>;
}

/** Checkers made in one assembly, its `max-concurrent` shared by them all; decoys from the kernel's random. */
export interface SecretCheckers {
	/** A checker computing, for each check, once per kind of work in use: the hashes' and the works named. */
	checkerOf(inUse: Iterable<SecretHash | SecretWork>): SecretChecker;
}

export const secretCheckers = contract<SecretCheckers>("secret-hash.checkers");

/** A bcrypt or scrypt hash, or undefined for anything else, plain text included. */
export function readSecretHash(text: string): SecretHash | undefined {
	return readHash(text);
}

/**
 * A work as a hash of it names its work (`bcrypt:12`, `scrypt:15,8,1,32,16`), within the bounds a hash
 * is read in, or undefined for anything else: the work a checker computes where no hash of it is.
 */
export function readSecretWork(text: string): SecretWork | undefined {
	return readWork(text);
}
