import type { Issued } from "@mod/approvals";
import type { ContinuationStageName } from "@mod/continuation-wire";
import { contract, extensionPoint } from "@mod/kernel";
import type { SigningKey } from "@mod/sdk-core-wire";

/**
 * A first key's start, which every item of evidence is bound to: the nonce the path gave the
 * screen, and the identifier asked for. The path owns the nonce, gives it a short life, and uses it
 * up before any kind checks: `prepare` runs while it is not yet used, `check` once for each kind
 * after, and none past its life.
 */
export interface FirstKeyStart {
	readonly nonce: string;
	readonly identifier: string;
}

/**
 * What a kind's check answers for the subject: its items passed, they failed, or the kind's own
 * record says the subject holds none of it. A record lost is no such word: it fails. A subject of
 * none fails. A fault is thrown, Unavailable. The answer stays in the path: the screen is answered
 * alike whichever it is. A kind asked of everyone never answers absent.
 */
export type EvidenceAnswer =
	| { readonly kind: "passed" }
	| { readonly kind: "failed" }
	| { readonly kind: "absent" };

/**
 * How the path ended a start: passed, failed (its own refusals too, such as a subject of none), or
 * a fault, a kind's or its own.
 */
export type StartOutcome = "passed" | "failed" | "unavailable";

/**
 * One kind of a first key's evidence beside the email's token: a password, a one-time code, a
 * security key, a login at the IdP the person is moved from. Each takes the start and the subject
 * the identifier names, or none where it names no one, and answers in the same shape, after the
 * same work, for a subject of none, one holding none of the kind, and one holding it, so no answer
 * tells who exists or what they hold.
 */
export interface FirstKeyEvidence {
	/** The kind's name: the one its module declares to `promises`' `evidenceKinds` too. */
	readonly kind: string;
	/**
	 * What the screen needs before it makes the items, bound to the start's nonce: a challenge and
	 * the keys allowed, a request to the IdP moved from. Alike in shape and work for a subject of
	 * none, one holding none of the kind, and one holding it, and alike for one identifier each time
	 * it is asked. A kind that needs nothing leaves it out.
	 */
	prepare?(
		start: FirstKeyStart,
		subject: string | undefined,
	): Promise<Readonly<Record<string, unknown>>>;
	/** Checks its own items, under its name in the request's map of kinds, as the screen sent them, unread by others. */
	check(start: FirstKeyStart, subject: string | undefined, items: unknown): Promise<EvidenceAnswer>;
	/**
	 * Told once for each start it checked, after every kind has answered, how the start ended: a
	 * password's module hands it to the owner of the password's waits. It may never come, the
	 * process gone or the call thrown, and a start not told is counted as not passed.
	 */
	settled?(start: FirstKeyStart, subject: string | undefined, outcome: StartOutcome): Promise<void>;
}

/** The kinds of a first key's evidence composed, one by its name. */
export const firstKeyEvidence = extensionPoint<FirstKeyEvidence>(
	"passkey-management.first-key-evidence",
	{ multiplicity: "keyed", keyOf: (evidence) => evidence.kind },
);

/** A record as one of the stores keeps it: opaque to the store. */
export interface Kept<T> {
	/** Keeps the record for its lifetime, unless one is kept already. */
	create(key: string, record: T, lifetimeMs: number): Promise<"created" | "exists">;
	read(key: string): Promise<T | undefined>;
	/**
	 * Changes the record from what it holds; `change` runs again on a lost race. None where none is
	 * kept. The record's lifetime stays as created: no change moves it.
	 */
	change(
		key: string,
		change: (current: T) => { readonly value: T } | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
}

declare const storedNonce: unique symbol;
/** A nonce of a first key's stage as kept. */
export type StoredNonce = { readonly [storedNonce]: true };

/** Where a first key's nonces are kept, by their value: no subject. Throws Unavailable when it cannot tell. */
export const firstKeyNonces = contract<Kept<StoredNonce>>("passkey-management.nonces");

/** What the nonces' place must be, each a guarantee its wiring declares. */
export const firstKeyNoncesNeeds = {
	/** A nonce lost to eviction or failover would let a sealed request be sent twice. */
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** A stale read could take a used nonce for a fresh one. */
	confirmedReads: true,
	/** A nonce written outside the provider would bind a request it never gave. */
	authenticated: true,
} as const;

declare const storedToken: unique symbol;
/** A mail token, or the answer its mail's side was given, as kept. */
export type StoredToken = { readonly [storedToken]: true };

/**
 * Where a first key's mail tokens, and the answers of its mail's side, are kept, by keys this
 * package names: each names a subject. Throws Unavailable when it cannot tell.
 */
export const firstKeyTokens = contract<Kept<StoredToken>>("passkey-management.tokens");

/** What the tokens' place must be, each a guarantee its wiring declares. */
export const firstKeyTokensNeeds = {
	/** A token lost to eviction would end a first key's path; an answer lost would hand out another. */
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** A stale read could count a code twice, or take a used token for a fresh one. */
	confirmedReads: true,
	/** A token written outside the provider would bind a first key to any subject. */
	authenticated: true,
} as const;

/** A first key's mail: its purpose, as `mail`'s purposes name it, and the values its wording is given. */
export const firstKeyMail = Object.freeze({
	purpose: "first-key",
	values: Object.freeze({
		/** The link to the mail's side, the token in its fragment. */
		link: "link",
		/** The account, its identifier masked. */
		account: "account",
		/** How many minutes the link lives. */
		minutes: "minutes",
	}),
});

/** A continuation as `/continue` read it, by the wire's sizes: the statement, its hash, and what the screen signed. */
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

/** This package's part of a subject's flow: a key change's preimage, kept beside passkeys' reservation for a resend. */
export const keyChangePart = "passkey-management";
