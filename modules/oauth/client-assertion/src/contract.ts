import type { Client } from "@mod/clients";
import { contract } from "@mod/kernel";

export { type ClientKeys, clientKeys, type Jwk } from "./keys/keys.ts";
export * from "./store.ts";

/** A JWT a client signed, as `verifySignedBy` reads it: its claims, or why not. */
export type SignedBy =
	| { readonly kind: "signed"; readonly claims: Readonly<Record<string, unknown>> }
	| { readonly kind: "refused"; readonly reason: string };

/** What the client's keys decide, for the modules that ask of a client's key or signature. */
export interface ClientAssertion {
	/**
	 * Whether the client holds the key a JWK SHA-256 thumbprint (RFC 7638) names: one of its keys
	 * written in, read under the operator's algorithms. A client whose keys are at a jwks-uri holds
	 * none here.
	 */
	holdsKey(client: Client, thumbprint: string): Promise<boolean>;
	/**
	 * A JWT signed by one of the client's keys, written or at its jwks-uri, under the operator's
	 * algorithms, clock allowance and longest lifetime, its header's `typ` the one asked: its claims,
	 * the rest the caller's. Throws Unavailable while its key set cannot be had.
	 */
	verifySignedBy(client: Client, jwt: string, typ: string): Promise<SignedBy>;
}

export const clientAssertion = contract<ClientAssertion>("client-assertion");
