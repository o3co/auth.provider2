import type { Client } from "@mod/clients";
import { deepFreeze } from "@mod/kernel";
import { thumbprint } from "@mod/keys";
import type { Jwk, VerifiedKey } from "./contract.ts";

/** The proofs this module made, so a value of the same shape made elsewhere is none of them. */
const made = new WeakSet<object>();

/** What an assertion's verification proves: the key that verified it, and the client's registry version. */
export async function proofOf(key: Jwk, client: Client): Promise<VerifiedKey> {
	const proof = deepFreeze({
		client: client.id,
		key: structuredClone(key),
		thumbprint: await thumbprint(key),
		...(client.version === undefined ? {} : { version: client.version }),
	});
	made.add(proof);
	return proof;
}

/** A proof this module made, for the client given where one is; none for anything else. */
export const verifiedOf = (proof: unknown, client?: Client): VerifiedKey | undefined => {
	if (typeof proof !== "object" || proof === null || !made.has(proof)) return undefined;
	const verified = proof as VerifiedKey;
	return client === undefined || verified.client === client.id ? verified : undefined;
};
