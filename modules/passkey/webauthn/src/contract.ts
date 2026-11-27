import { contract } from "@mod/kernel";

/** WebAuthn's user verification requirement; only `required` refuses a response without it. */
export type Verification = "required" | "preferred" | "discouraged";

/** A credential to check assertions with; ids, keys and handles are unpadded base64url. Its holder may keep it. */
export interface Credential {
	readonly id: string;
	readonly publicKey: string;
	readonly signCount: number;
	readonly userHandle: string;
	readonly backupEligible: boolean;
	readonly backedUp: boolean;
	readonly transports?: readonly string[];
}

export type CeremonyRefusal =
	| "malformed"
	| "challenge"
	| "origin"
	| "top-origin"
	| "rp"
	| "algorithm"
	| "signature"
	| "sign-count"
	| "user-handle"
	| "user-verification"
	| "backup-eligibility";

export type Asserted =
	/** `credential` carries the new sign count and backup state, for the holder to keep. */
	| { readonly kind: "asserted"; readonly credential: Credential; readonly userVerified: boolean }
	| { readonly kind: "refused"; readonly reason: CeremonyRefusal };

/**
 * Ceremonies over a challenge the caller gives: 32 bytes, unpadded base64url, used as it is. The
 * caller keeps it and its credential, judges how long it can be answered, and hands both over once.
 * Verification is `required` where none is asked.
 */
export interface Ceremonies {
	/** Options for a new credential over `challenge`; a discoverable one unless told otherwise. */
	creation(
		challenge: string,
		user: { readonly handle: string; readonly name: string },
		exclude: readonly string[],
		v?: Verification,
		asked?: { readonly discoverable?: boolean },
	): unknown;
	attest(
		response: unknown,
		challenge: string,
		handle: string,
		v?: Verification,
	): Promise<
		| { readonly kind: "attested"; readonly credential: Credential }
		| { readonly kind: "refused"; readonly reason: CeremonyRefusal }
	>;
	/** Options for an assertion by one of `allow` (none: any discoverable credential) over `challenge`. */
	request(challenge: string, allow: readonly Credential[], v?: Verification): unknown;
	/** `named`: whether the request over `challenge` named credentials, as the caller kept it, never as the client says. */
	assert(
		response: unknown,
		asked: { readonly challenge: string; readonly named: boolean },
		credential: Credential,
		v?: Verification,
	): Promise<Asserted>;
	/**
	 * Evidence checked at once and against no credential state (authority-rules' `Checks.verifyAssertion`):
	 * `assertion` the JSON of an assertion response, `publicKey` the key's COSE_Key in base64url, of any
	 * algorithm a passkey may be of whatever the relying party offers.
	 * The assertion's credential id where it verifies, as `assert` requiring verification would, for
	 * `challenge` and `origin`; none otherwise, never a throw.
	 */
	verifyAssertion(
		assertion: string,
		publicKey: string,
		challenge: string,
		origin: string,
	): { readonly credential: string } | undefined;
	/**
	 * The same evidence check again, at a rooted refresh, for an assertion taken at an approval: for
	 * whichever of `origins` its client data names (the origin was judged when it was taken), by the
	 * same rules as `verifyAssertion` otherwise. Its credential id where it verifies; none, never a throw.
	 */
	reverifyAssertion(
		assertion: string,
		publicKey: string,
		challenge: string,
	): { readonly credential: string } | undefined;
	/**
	 * A `create()` response's JSON as sent, read at once and against no state (authority-rules'
	 * `Checks.attestedKey`): its credential id and the new key, its COSE_Key in base64url, as `attest`
	 * reads them from the attestation's authenticator data, the key read whole. Read, not verified: no
	 * challenge, origin or signature is judged. None for one that does not read, never a throw.
	 */
	attestedKey(
		response: string,
	): { readonly credential: string; readonly publicKey: string } | undefined;
	/** Whether a ceremony may come from `origin`, as attestation and assertion match it: exactly, against `origins`. */
	allowsOrigin(origin: string): boolean;
}

export const ceremonies = contract<Ceremonies>("webauthn.ceremonies");

export { keyThumbprint, passkeyJwk } from "./keys.ts";
export { credentialLimits, credentialOf, freshHandle, isCanonical } from "./records.ts";
