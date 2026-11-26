import type { Issued, Screen } from "@mod/approvals";
import type { ContinuationStageName } from "@mod/continuation-wire";
import { contract, extensionPoint } from "@mod/kernel";
import type { SigningKey } from "@mod/sdk-core-wire";

/** A continuation as `/continue` read it, by the wire's spec: the statement, its hash, and what the screen signed. */
export type ContinueAsk = {
	readonly stage: ContinuationStageName;
	/** The request's source, as its rate is counted (`rate-limit`'s `sourceKey`). */
	readonly source: string;
	readonly statement: string;
	/** SHA-256 of the statement, base64url: the key its record is kept by. */
	readonly hash: string;
	readonly seq: number;
} & (
	| {
			/** The body as received, and E_sig's `r‖s`, base64url: a stage in the clear. */
			readonly body: string;
			readonly signature: string;
	  }
	| {
			/** The body and signature sealed to the Core: a stage `continuation-wire` seals. */
			readonly sealed: { readonly enc: string; readonly ct: string };
	  }
);

/** A continuation's answer: a statement or a sealed value, as the wire's forms give its stage; or refused, its reason for the log alone. */
export type ContinueAnswer =
	| { readonly kind: "statement"; readonly statement: string }
	| { readonly kind: "sealed"; readonly enc: string; readonly ct: string }
	| { readonly kind: "refused"; readonly reason: string };

/**
 * One stage of `/continue`, contributed by the module whose ceremony it continues: its word, as
 * `continuation-wire` names it, and how it goes on, by its own step through `approvals`. A fault, or
 * a store that cannot tell, it throws.
 */
export interface ContinueStage {
	readonly stage: ContinuationStageName;
	continue(q: ContinueAsk): Promise<ContinueAnswer>;
}

/** The stages `/continue` takes: one module each, boot refusing a stage two contribute. */
export const continueStages = extensionPoint<ContinueStage>("passkey-management.continue-stages", {
	multiplicity: "many",
});

/**
 * A sign-up's (F1) creation asked, by the `sign-up` package once the ledger made its subject: T's
 * hash (the creation's evidence), the new subject, T's screen keys as approvals keeps them, and
 * when T was issued (a revocation of the subject since refuses it).
 */
export interface SignUpAsk {
	readonly tHash: string;
	readonly subject: string;
	readonly screen: { readonly eEnc: string; readonly eSig: SigningKey };
	readonly since: number;
}

/**
 * A sign-up's creation: issued, or refused `revoked` where the subject was. A passing failure (a
 * count reached, a signing busy, the ring withdrawn) is thrown, never answered, so it is not kept.
 */
export type SignUpCreated =
	| Extract<Issued, { readonly kind: "issued" }>
	| { readonly kind: "refused"; readonly reason: "revoked" };

/**
 * Makes a sign-up's creation (F1): basis `sign-up`, its account named in `user_name` alone by the
 * deployment's name and a short mark of the subject, for T's screen. Taken by the module whose flow
 * makes the subject; the registration that follows is this package's.
 */
export const signUpCreations = contract<{ create(ask: SignUpAsk): Promise<SignUpCreated> }>(
	"passkey-management.sign-up-creations",
);

/**
 * A first key's creation asked, by the first key's path once its token and evidence passed: the
 * subject the token binds, the identifier the person named, the sealed request's digest, the
 * evidence's value, the screen's keys, and when the evidence began (a revocation since refuses it).
 */
export interface FirstKeyCreationAsk {
	readonly subject: string;
	readonly identifier: string;
	readonly ctHash: string;
	readonly evidence: string;
	readonly screen: Screen;
	readonly since: number;
}

/**
 * A first key's creation: issued, or refused `revoked` or `full`. A passing failure (a count
 * reached, a signing busy, the ring withdrawn, a statement too long) is thrown Unavailable, never
 * answered; items the schema refuses are a fault.
 */
export type FirstKeyCreated =
	| Extract<Issued, { readonly kind: "issued" }>
	| { readonly kind: "refused"; readonly reason: "revoked" | "full" };

/**
 * Makes a first key's creation: basis `first-key`, its `account` the identifier `masked`, its
 * `ct_hash` the sealed request's digest, for the screen. The registration that follows is this
 * package's. Taken by `first-key` alone: it mints a creation on that path's checks.
 */
export const firstKeyCreations = contract<{
	create(ask: FirstKeyCreationAsk): Promise<FirstKeyCreated>;
}>("passkey-management.first-key-creations", { takenBy: ["first-key"] });

/** How an identifier shows, in a creation's `account` and in a first key's mail: its first character, and an address's domain. */
export { masked } from "./account.ts";

/** This package's part of a subject's flow: a key change's preimage, kept beside passkeys' reservation for a resend. */
export const keyChangePart = "passkey-management";

/** What the part's place must be, each a guarantee its wiring declares: as transparency's frames, written in their writes. */
export const keyChangePartNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	readsConfirmed: true,
	authenticated: true,
} as const;
