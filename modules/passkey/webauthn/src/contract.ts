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
}

export const ceremonies = contract<Ceremonies>("webauthn.ceremonies");

export { challengeOf } from "./ceremony/ceremony.ts";
export { credentialLimits, credentialOf, freshHandle, isCanonical } from "./records.ts";
