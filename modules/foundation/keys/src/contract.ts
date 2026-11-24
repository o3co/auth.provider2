import type { KeyObject } from "node:crypto";
import { contract } from "@mod/kernel";
import { stances } from "@mod/promises";
import type { Jwk } from "./material/public.ts";

/**
 * The provider's two rings: the authority's, whose keys sign the tokens it issues and whose public
 * keys are the JWKS, and the Core's, whose keys sign the statements and the completion's answer and
 * whose public keys the login screen pins, one key for each Core generation.
 */
export type Ring = "authority" | "core";

export type VerifyResult =
	| { readonly kind: "valid"; readonly claims: Readonly<Record<string, unknown>> }
	| {
			readonly kind: "invalid";
			readonly reason: "malformed" | "typ" | "kid_unknown" | "kid_expired" | "signature";
	  };

/** A signature asked for: the compact JWS, or `withdrawn` where the keys' holder no longer lets this Core sign. */
export type Signed =
	| { readonly kind: "signed"; readonly jws: string }
	| { readonly kind: "withdrawn" };

/** One HPKE sealing: the sender's encapsulated key and the ciphertext, each as bytes. */
export interface Sealed {
	readonly enc: Uint8Array;
	readonly ct: Uint8Array;
}

/** A sealing opened, one that does not open, or `withdrawn` where the holder no longer lets this Core open. */
export type Opened =
	| { readonly kind: "opened"; readonly plaintext: Uint8Array }
	| { readonly kind: "unopened" }
	| { readonly kind: "withdrawn" };

/**
 * What the keys' holder can do beyond signing, for the parts that stop and watch the Core: whether
 * its signing and opening can be withdrawn from the Core outside it, and whether each call is counted
 * outside the Core's account.
 */
export interface Powers {
	readonly withdrawable: boolean;
	readonly countedOutside: boolean;
}

/** A run of `keys-publish`: the lines it writes and its exit code. */
export interface Published {
	readonly lines: readonly string[];
	readonly code: number;
}

/** A JWS protected header, as keys writes it. */
export interface Header {
	readonly alg: string;
	readonly typ: string;
	readonly kid: string;
}

/**
 * A signature made ready: the ring and the header fixed before anything is signed, so a caller can
 * take a digest of the header and its claims first. `headerText` is the protected header's bytes,
 * as `sign` writes them.
 */
export interface Prepared {
	readonly ring: Ring;
	readonly header: Header;
	readonly headerText: string;
}

/** A compact JWS verified against keys given: its header and payload as read. */
export interface Read {
	readonly header: unknown;
	readonly payload: unknown;
}

export interface Keys {
	/** The header the ring's signing key signs under `typ` with, fixed for `sign`. */
	prepare(ring: Ring, typ: string): Prepared;
	/** The compact JWS of `payload`, a JSON object's UTF-8 bytes signed as given, under the header prepared. */
	sign(prepared: Prepared, payload: Uint8Array): Promise<Signed>;
	/** Verified by the ring's keys: the authority's unexpired ones, the Core's current generation's alone. */
	verify(ring: Ring, token: string, typ: string): Promise<VerifyResult>;
	/** Verified by the key of the Core generation named. */
	verifyOf(generation: number, token: string, typ: string): Promise<VerifyResult>;
	/** The Core generation this Core signs as. */
	generation(): number;
	/** The public keys of the Core generation named (each with its kid, alg and generation), or none. */
	coreRing(generation: number): readonly Jwk[] | undefined;
	/** A compact JWS verified by the key of `keys` (JWKs) its kid names, at once: its header and payload, or none. */
	verifyJws(jws: string, keys: readonly unknown[]): Read | undefined;
	/** The JWS `alg` the ring signs with now. */
	algorithm(ring: Ring): string;
	/** The JWS `alg` the ring's next key will sign with, where it has one. */
	nextAlgorithm(ring: Ring): string | undefined;
	/** Seals `plaintext` to a P-256 point (uncompressed) under an info sdk-core-wire or transparency-wire names. */
	seal(to: Uint8Array, info: string, aad: Uint8Array, plaintext: Uint8Array): Promise<Sealed>;
	/** Opens what a screen sealed to the Core's sealing key, under one of sdk-core-wire's `hpke.info`. */
	open(sealed: Sealed, info: string, aad: Uint8Array): Promise<Opened>;
	powers(): Powers;
	/** `keys-publish <directory>`: writes the two rings' public keys there, as `jwks.json` and `core-keys.json`. */
	publish(args: readonly string[]): Promise<Published>;
}

/** Taken only by a module that declares where it stands on the promises. */
export const keys = contract<Keys>("keys", { takersContribute: stances });

/** Signs and verifies access tokens (`at+jwt`) with the authority's ring. */
export interface AccessTokenSigning {
	prepare(): Prepared;
	sign(prepared: Prepared, payload: Uint8Array): Promise<Signed>;
	verify(token: string): Promise<VerifyResult>;
}

/**
 * Taken by `tokens` alone, so no other module of a composition signs or verifies an access token,
 * and only as it declares where it stands on the promises.
 */
export const accessTokenSigning = contract<AccessTokenSigning>("keys.access-signing", {
	takenBy: ["tokens"],
	takersContribute: stances,
});

/** A key the holder holds, by the kid `keys` names it. */
export interface Held {
	readonly publicKey: KeyObject;
	/** The JWS algorithms the holder signs with it under; none where it holds its public half alone. */
	readonly signsUnder: readonly string[];
	/** Whether the holder agrees a P-256 Diffie-Hellman secret with it. */
	readonly agrees: boolean;
}

/** A signature over the bytes given, written as a JWS writes it, or `withdrawn`. */
export type SignAnswer =
	| { readonly kind: "signed"; readonly signature: Uint8Array }
	| { readonly kind: "withdrawn" };

/** The Diffie-Hellman secret agreed with a peer's point, or `withdrawn`. */
export type AgreeAnswer =
	| { readonly kind: "agreed"; readonly shared: Uint8Array }
	| { readonly kind: "withdrawn" };

/**
 * The keys axis: the adapter that holds the keys, signs with them and agrees with them, and says
 * what it can do beyond (`powers`). `keys` keeps what the keys mean; the holder reads none of it.
 */
export interface KeyHolder {
	readonly powers: Powers;
	held(kid: string): Held | undefined;
	sign(kid: string, alg: string, input: Uint8Array): Promise<SignAnswer>;
	agree(kid: string, peer: KeyObject): Promise<AgreeAnswer>;
}

export { isCanonicalJws } from "./material/jws.ts";
export {
	isVerifyAlgorithm,
	type Jwk,
	type PemForm,
	publicJwk,
	publicMembers,
	publicPem,
	thumbprint,
	type VerifyAlgorithm,
	verifiesUnder,
	verifyAlgorithms,
} from "./material/public.ts";
export { bearerToken, secretBytes } from "./secret/secret.ts";
