import type { Client } from "@mod/clients";
import { deepFreeze } from "@mod/kernel";
import { thumbprint } from "@mod/keys";
import type { Jwk, VerifiedKey } from "./contract.ts";

/** The proofs this module made, so a value of the same shape made elsewhere is none of them. */
const made = new WeakSet<object>();

/** What an assertion's verification proves: the key, the client's registry version, and whether the key is written. */
export async function proofOf(key: Jwk, client: Client, written: boolean): Promise<VerifiedKey> {
	const proof = deepFreeze({
		client: client.id,
		key: structuredClone(key),
		thumbprint: await thumbprint(key),
		...(client.version === undefined ? {} : { version: client.version }),
		...(written ? { written: true as const } : {}),
	});
	made.add(proof);
	return proof;
}

/** A proof this module made, for the client it verified; none for anything else. */
export const verifiedOf = (proof: unknown, client: Client): VerifiedKey | undefined => {
	if (typeof proof !== "object" || proof === null || !made.has(proof)) return undefined;
	const verified = proof as VerifiedKey;
	return verified.client === client.id ? verified : undefined;
};
