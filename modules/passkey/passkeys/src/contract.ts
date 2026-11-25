import { contract, extensionPoint } from "@mod/kernel";
import { stances } from "@mod/promises";
import type { Deciding, Refused } from "@mod/transparency";
import type { CeremonyRefusal, Credential } from "@mod/webauthn";
import { keyChanges, part } from "./records.ts";

/**
 * Passkeys: each subject's keys as its flow's state holds them, the reservation of a key being
 * registered, and each credential's record. Every call throws Unavailable when a store cannot tell.
 */

/** The part its records are in: the subject flow's keys and its one reservation. */
export const passkeyPart = part;

/**
 * The key change's kind of operation, but for its `bundle` and `resend`: its name, its part, its
 * records (the reservation) and its end, which confirms the reservation (`took`) or releases it. The
 * key change's writer registers it on `transparency`'s `operationKinds`, with its own two, and may
 * append records of its own after passkeys' (its preimage, for a resend), whose end it answers.
 */
export const passkeyChanges = keyChanges;

export type AssertRefusal = CeremonyRefusal | "unknown-credential" | "not-named" | "raced";

/** What the approval path and the judgment ask of the keys kept. */
export interface Passkeys {
	/**
	 * An assertion by an active key, over the challenge and the credentials its request named
	 * (`allow`, none for any discoverable one), both as the caller kept them with its request.
	 */
	assert(
		response: unknown,
		asked: { readonly challenge: string; readonly allow: readonly string[] },
	): Promise<
		| {
				readonly kind: "asserted";
				readonly subject: string;
				readonly credential: string;
				/** The id of the key's registration's record on the subject's flow, as `publicKeyOf` names it, from the read that verified the assertion. */
				readonly registration: string;
				readonly userVerified: boolean;
				readonly backupEligible: boolean;
		  }
		| { readonly kind: "refused"; readonly reason: AssertRefusal }
	>;
	/**
	 * An active key's public key and subject, and the id of its registration's record on the subject's
	 * flow (the key's id in the flow's state); none for any other credential.
	 */
	publicKeyOf(
		credential: string,
	): Promise<
		| { readonly subject: string; readonly publicKey: string; readonly registration: string }
		| undefined
	>;
	/**
	 * After a key change ended, by whoever took the end in: from the applied state alone, tells
	 * `passkeyRemovals` of each credential gone since the last settle, sets the witness's mark while
	 * the subject holds a key, reading the keys again after to withdraw it where a boundary moved the
	 * generation on meanwhile, and withdraws marks of generations before the current. Idempotent.
	 * Whether the subject holds a key.
	 */
	settle(subject: string): Promise<boolean>;
}

export const passkeys = contract<Passkeys>("passkeys");

/**
 * A subject's key generation, as its applied state holds it (resets that took, and erasures): what an
 * embedder's reset instruction names as `kg` on L0's path. The applied state may lag the log's head
 * (a boundary not yet taken in), never lead it: read after a `tend`. L1's embedder reads the
 * monitor's signed `stateOf` instead, never a Core's answer (V22 §B.6).
 */
export interface PasskeyGenerations {
	generation(subject: string): Promise<number>;
}

export const passkeyGenerations = contract<PasskeyGenerations>("passkeys.generations");
/** A subject's keys as read, nothing written; its key generation is `passkeyGenerations`'. */
export interface Held {
	/** The credentials of its keys. */
	readonly credentials: readonly string[];
	/**
	 * Whether the witness's mark is set, of whatever generation: after a `settle`, this generation's
	 * alone. A first key's reservation takes a subject holding no key and no mark.
	 */
	readonly marked: boolean;
	/** Set where it holds `max-credentials` keys: a key added to them is refused (`full`). */
	readonly full?: true;
	/** Its one reservation waiting for its key's possession, unlapsed; none otherwise. */
	readonly pending?: {
		readonly reservation: string;
		readonly credential: string;
		/** The reserved key's COSE_Key, base64url, as webauthn attested it. */
		readonly publicKey: string;
	};
}

/**
 * Reads a subject's keys, its pending reservation and the witness's mark, writing nothing: the same
 * reads for a subject no flow holds. Anyone may take it.
 */
export const heldKeys = contract<{ of(subject: string): Promise<Held> }>("passkeys.held");

/** An active key as the keys' list shows it: its label and reservation time, where its record holds them. */
export interface KeyRow {
	readonly credential: string;
	readonly label?: string;
	readonly createdAt?: number;
}

/** A subject's keys listed, and a key renamed; nothing here bears on what a key may approve. */
export interface KeyList {
	/** Each active key of the subject's, in the applied state's order. */
	listOf(subject: string): Promise<readonly KeyRow[]>;
	/**
	 * Gives an active key of the subject's a label, by a statement's continuation (`by`: the
	 * statement's hash, the continuation's number, and `until`, past which no step of that statement
	 * runs): `stale` past `until`, or for a number of a statement still running below the last it
	 * renamed by, or its own number with another label; that number with that label again is `renamed`.
	 */
	rename(p: {
		readonly subject: string;
		readonly credential: string;
		readonly label: string;
		readonly by: { readonly statement: string; readonly seq: number; readonly until: number };
	}): Promise<"renamed" | "unknown" | "stale" | "label">;
}

/** Taken only by a module that declares where it stands on the promises: a label guides a person's choice of key. */
export const keyList = contract<KeyList>("passkeys.keyList", { takersContribute: stances });

export type ReserveRefusal = "pending" | "held" | "taken" | "fenced" | "unknown" | "state" | "open";
export type VerifyRefusal = CeremonyRefusal | "unknown" | "state" | "expired" | "open";

/** A key change of a subject's flow, decided as its writer's op (`transparency`'s KE-C01). */
export interface KeyChange {
	readonly subject: string;
	/** The writer's part of KE-C01; its changes name the key the change is of. */
	readonly decide: Deciding;
}
export type Decided = { readonly prev: number } | Refused<string>;

/** Registering keys, in the order reserve, verifyPending, commit; and removing one. */
export interface Registrations {
	/**
	 * Reserves `credential` for the subject under `generation`, the key generation its approval names
	 * (`fenced` where the flow's is another): refused while another is pending, unless `retrying` it
	 * (whose key generation it keeps). `first`: only where the subject holds no key and no mark.
	 */
	reserve(p: {
		readonly subject: string;
		readonly credential: Credential;
		readonly generation: number;
		readonly first?: boolean;
		readonly retrying?: string;
	}): Promise<{ readonly reservation: string } | { readonly refused: ReserveRefusal }>;
	/**
	 * Checks an assertion by the reserved key, over a request naming it alone; the key stays pending.
	 * The response and challenge that verified it are answered alike again, its count saved first.
	 */
	verifyPending(p: {
		readonly subject: string;
		readonly reservation: string;
		readonly response: unknown;
		readonly challenge: string;
	}): Promise<
		| { readonly verification: string; readonly userVerified: boolean }
		| { readonly refused: VerifyRefusal }
	>;
	/** KE-C01 of the reservation's key change, its op the reservation: only a verified one, verified so. */
	commit(
		p: KeyChange & { readonly reservation: string; readonly verification: string },
	): Promise<Decided>;
	/** Releases a reservation no op is putting on the log, and its credential's binding where never active. */
	cancel(p: {
		readonly subject: string;
		readonly reservation: string;
	}): Promise<{ readonly cancelled: true } | { readonly refused: "unknown" | "state" | "open" }>;
	/**
	 * KE-C01 of a removal: refused where the subject would hold no key after it (`last`), and for the
	 * reservation's op (`op`).
	 */
	remove(p: KeyChange & { readonly credential: string; readonly op: string }): Promise<Decided>;
}

/** Taken only by a module that declares where it stands on the promises. */
export const registrations = contract<Registrations>("passkeys.registrations", {
	takersContribute: stances,
});

/**
 * Who keeps the witness's mark in line with the keys, a mark for a key generation; contributed where a
 * witness is composed.
 */
export interface PasskeyWitnessing {
	/** Whether the subject carries a mark, whichever generation set it. */
	marked(subject: string): Promise<boolean>;
	/** Sets the mark for `generation` unless one of that generation or a later is set; one of a generation before is replaced. */
	mark(subject: string, generation: number): Promise<void>;
	/** Withdraws any mark of a generation before `generation`. */
	withdraw(subject: string, generation: number): Promise<void>;
}

/** At most one; with none (composed by hand), the keys alone tell, and a passkey witness composed refuses boot. */
export const passkeyWitnessing = extensionPoint<PasskeyWitnessing>("passkeys.witnessing", {
	multiplicity: "many",
});

/**
 * Told of a credential a subject holds no more, at least once for the latest 64 taken off between two
 * settles (an older one goes untold); `emptied`: the subject holds no key after. Throws Unavailable
 * where it cannot tell: it is told again at the next settle.
 */
export interface PasskeyRemoval {
	removed(subject: string, credential: string, emptied: boolean): Promise<void>;
}

export const passkeyRemovals = extensionPoint<PasskeyRemoval>("passkeys.removals", {
	multiplicity: "many",
});

declare const storedCredential: unique symbol;
/** A credential's record as the store keeps it: only passkeys opens it. */
export type StoredCredential = { readonly [storedCredential]: true };

/** Each credential's record, by its id, kept without end. */
export interface PasskeyStore {
	/** Keeps the credential's first record, unless it holds one. */
	create(credential: string, record: StoredCredential): Promise<"created" | "exists">;
	read(credential: string): Promise<StoredCredential | undefined>;
	/** Changes the record from what it holds; `change` runs again on a race, so it is pure; none leaves it. */
	change(
		credential: string,
		change: (record: StoredCredential) => { readonly value: StoredCredential } | undefined,
	): Promise<{ readonly before: StoredCredential; readonly after: StoredCredential } | undefined>;
}

export const passkeyStore = contract<PasskeyStore>("passkeys.store");

/** A record lost or come back would point a key at another subject or move its count back. */
export const passkeyStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
	/** A record written outside the provider would name another subject's key. */
	authenticated: true,
} as const;
