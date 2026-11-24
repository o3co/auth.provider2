import type { Client } from "@mod/clients";
import { contract } from "@mod/kernel";
import type { Jwk } from "./keys/keys.ts";

export { type ClientKeys, clientKeys, type Jwk } from "./keys/keys.ts";
export * from "./store.ts";

/** A JWT a client signed, as `verifySignedBy` reads it: its claims, or why not. */
export type SignedBy =
	| { readonly kind: "signed"; readonly claims: Readonly<Record<string, unknown>> }
	| { readonly kind: "refused"; readonly reason: string };

/** The key a client's assertion was verified with, its JWK SHA-256 thumbprint, and the registry version the client came from. */
export interface VerifiedKey {
	/** The client it verified. */
	readonly client: string;
	readonly key: Jwk;
	readonly thumbprint: string;
	readonly version?: number;
}

/** What the client's keys decide, for the modules that ask of a client's key or signature. */
export interface ClientAssertion {
	/**
	 * The key an authentication by this module's assertion was verified with, from its `proof` as
	 * `clients` carries it, for the client it verified; none for any other value, a proof of another
	 * method's, one made elsewhere, or one of another client. `client` is optional while its readers move.
	 */
	verifiedOf(proof: unknown, client?: Client): VerifiedKey | undefined;
	/**
	 * A JWT signed by one of the client's keys, written or at its jwks-uri, under the operator's
	 * algorithms, clock allowance and longest lifetime, its header's `typ` the one asked: its claims,
	 * the rest the caller's. Throws Unavailable while its key set cannot be had.
	 */
	verifySignedBy(client: Client, jwt: string, typ: string): Promise<SignedBy>;
}

export const clientAssertion = contract<ClientAssertion>("client-assertion");
