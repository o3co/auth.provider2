import { contract, extensionPoint } from "@mod/kernel";
import type { AssertRefusal } from "@mod/passkeys";
import { stances } from "@mod/promises";
import type {
	AuthorizationItems,
	CreationPayload,
	PossessionPayload,
	SigningKey,
} from "@mod/sdk-core-wire";
import { part } from "./completion/completion.ts";

/** The purposes a statement is signed for: the IdP's own operations, a closed set. */
export type Purpose = "authorization" | "passkey-add" | "creation" | "possession";

/** Each purpose's items, as sdk-core-wire fixes them. */
export interface ItemsOf {
	readonly authorization: AuthorizationItems;
	/** A passkey-add names no items: only the common fields and the screen's keys. */
	readonly "passkey-add": Readonly<Record<string, never>>;
	readonly creation: CreationPayload["creation"];
	readonly possession: PossessionPayload["possession"];
}

/** The screen's two keys: HPKE's raw P-256 point (base64url) and its signing key. */
export interface Screen {
	readonly eEnc: string;
	readonly eSig: SigningKey;
}

/** The stages a T may be continued by, its owner allowing them at its issue: F1's sign-up. */
export type TStage = "sign-up";

/** A statement asked: its purpose and items, the screen's keys, and the key its issuing is counted by. */
export type IssueAsk = {
	readonly [P in Purpose]: {
		readonly purpose: P;
		readonly items: ItemsOf[P];
		readonly screen: Screen;
		readonly by: string;
		/** A T's alone: the stages it may be continued by, as its owner allows them; none where absent. */
		readonly continues?: P extends "authorization" ? readonly TStage[] : never;
	};
}[Purpose];

export type Issued =
	| {
			readonly kind: "issued";
			/** The compact JWS, `approval+jwt`, by the Core's ring. */
			readonly statement: string;
			/** Its SHA-256, base64url: the key its record is kept by. */
			readonly hash: string;
			/** What a `get()` over it is asked with: sdk-core-wire's challenge input, hashed. */
			readonly challenge: string;
	  }
	| { readonly kind: "refused"; readonly reason: "items" | "limited" | "busy" | "withdrawn" };

/** A statement used once: what its purpose's owner takes, from the record alone. */
export interface Approval {
	readonly hash: string;
	readonly purpose: Purpose;
	readonly items: ItemsOf[Purpose];
	/** By an assertion: the subject and credential it showed. */
	readonly subject?: string;
	readonly credential?: string;
	/** By an assertion: the id of that key's registration's record on the subject's flow, as passkeys answered it. */
	readonly registration?: string;
	/** By a possession: the verification passkeys gave the pending key. */
	readonly verification?: string;
	/** When it was used, by the kernel's clock, in ms: the same evidence again answers the same time. */
	readonly usedAt?: number;
	/** Set once its completion is kept, an authorization's or a key change's, whether or not it went out yet. */
	readonly completed?: true;
	/** When its statement was issued, in ms: where the proof of the login it approves began. */
	readonly issuedAt: number;
	/** Its statement's E_sig's thumbprint (RFC 7638's SHA-256, base64url), as an ID token's `esig` names it. */
	readonly esig: string;
}

export type UseRefusal = AssertRefusal | "unknown" | "expired" | "used" | "purpose" | "unverified";

export type Used =
	| { readonly kind: "approved"; readonly approval: Approval }
	| { readonly kind: "refused"; readonly reason: UseRefusal };

/**
 * A key change's completion asked: the possession it answers, whose items name the key added, the
 * path's purpose, and what the change's record was given on the log, as sdk-core-wire's `keyChange`
 * names them.
 */
export interface KeyChangeAsk {
	readonly hash: string;
	readonly purpose: "first-key" | "passkey-add" | "sign-up";
	readonly receipt?: string;
	readonly status?: string;
	readonly stateOf?: string;
}

export type KeyChangeCompleted =
	| {
			readonly kind: "completed";
			/** The completion, sealed to the possession's `eEnc`: HPKE's `enc` and ciphertext, base64url. */
			readonly enc: string;
			readonly ct: string;
	  }
	| {
			readonly kind: "refused";
			/**
			 * `unknown`: no record, or one this generation's ring does not verify. `purpose`: a statement
			 * no possession. `unused`: a possession not used. `expired` comes after a change took too: its
			 * screen learns of the key from the keys' list. `other`: kept for another path's purpose.
			 * `form`: one sdk-core-wire's `keyChange` refuses. `withdrawn`: the ring signs no more. A
			 * sign-up's: `creation`, a possession of no creation its T's sign-up answered; `other`, a T
			 * that kept another credential.
			 */
			readonly reason:
				| "unknown"
				| "purpose"
				| "unused"
				| "expired"
				| "other"
				| "creation"
				| "form"
				| "withdrawn";
	  };

/**
 * A creation as its record keeps it, the one purpose continued: its items as signed (the subject among
 * them), and the screen's keys it was signed for.
 */
export interface KeptCreation {
	readonly items: ItemsOf["creation"];
	readonly screen: Screen;
}

/**
 * A T as its record keeps it, for its sign-up's step: its hash, its bytes as signed, its items and the
 * screen's keys it was signed for.
 */
export interface KeptSignUp {
	readonly hash: string;
	readonly statement: string;
	/** When T was issued, in ms, as its signed `iat` says: a revocation of the subject since refuses the creation. */
	readonly issuedAt: number;
	readonly items: ItemsOf["authorization"];
	readonly screen: Screen;
}

/**
 * What a sign-up's step answers, kept on its T: the creation made for it (a compact JWS), or a refusal
 * its owner names, kept as one so the same continuation answers it again. A T that kept a refusal
 * keeps its sign-up begun, so no key uses it: its screen asks the authorization again. A passing
 * failure is thrown, never kept, so the step runs again.
 */
export type SignUpResult = { readonly creation: string } | { readonly refused: string };

/**
 * A T's sign-up as its record keeps it (F1): its bytes as signed, the subject made for it, the creation
 * its step answered (a compact JWS) and the credential its key change registered, each once kept.
 */
export interface SignUp {
	readonly statement: string;
	readonly subject?: string;
	readonly creation?: string;
	readonly credential?: string;
}

/**
 * A passkey-add's completion asked: the statement's hash, the assertion that used it (its JSON text as
 * received), and, to make one where none is kept, the creation its caller made for it.
 */
export interface PasskeyAddAsk {
	readonly hash: string;
	readonly assertion: string;
	readonly creation?: string;
}

export type PasskeyAddCompleted =
	| {
			readonly kind: "completed";
			/** The completion, sealed to the passkey-add's `eEnc`: HPKE's `enc` and ciphertext, base64url. */
			readonly enc: string;
			readonly ct: string;
	  }
	| {
			readonly kind: "refused";
			/**
			 * `unknown`: no record, one this generation's ring does not verify, or, asked with no creation,
			 * none kept yet. `purpose`: no passkey-add. `assertion`: another than the one that used it.
			 * `unused`: not used. `creation`: none issued here for it with basis `passkey-add`, its hash as
			 * evidence, its subject and the same screen's keys. `form`: one sdk-core-wire's `passkeyAdd` refuses.
			 * `withdrawn`: the ring signs no more.
			 */
			readonly reason:
				| "unknown"
				| "purpose"
				| "assertion"
				| "unused"
				| "expired"
				| "creation"
				| "form"
				| "withdrawn";
	  };

/**
 * A used passkey-add as the key change it approves takes it: its statement as signed, the assertion's
 * JSON text as received, the subject, credential and registration of the key that made it, the screen's
 * keys, and the flow state's use-once mark of the statement, which that key change consumes.
 */
export interface UsedPasskeyAdd {
	readonly statement: string;
	readonly assertion: string;
	readonly subject: string;
	readonly credential: string;
	readonly registration: string;
	readonly screen: Screen;
	readonly mark: string;
}

/** A creation's record as kept, apart from a continuation: its statement's bytes, its items and the screen's keys. */
export interface CreationRecord extends KeptCreation {
	readonly statement: string;
}

/** What a continuation's step answers, kept as JSON. */
export type StepResult =
	| null
	| boolean
	| number
	| string
	| readonly StepResult[]
	| { readonly [key: string]: StepResult };

export type Continued =
	| {
			readonly kind: "continued";
			readonly seq: number;
			/** Whether another call took this sequence number first. */
			readonly again: boolean;
			/** What its step answered: run once it was taken, kept, and given again alike. */
			readonly result: StepResult;
	  }
	| {
			readonly kind: "refused";
			/**
			 * `pending`: another call holds that continuation's step; ask again. `body`: one past 8192
			 * bytes, or a sign-up's other than `{}`. `signature`: one not the screen's, or not in its one
			 * spelling. `purpose`: a statement its stage does not continue, or a T whose owner did not allow
			 * it. `used`: a T no longer issued. `seq`: a number not the next, or a sign-up's other than 1.
			 */
			readonly reason:
				| "unknown"
				| "expired"
				| "purpose"
				| "body"
				| "signature"
				| "seq"
				| "pending"
				| "used";
	  };

/**
 * A creation's last continuation as taken: its sequence number, its body as received, the screen's
 * signature (`r‖s`, base64url) and, once kept, what its step answered, all from one read.
 */
export interface LastContinuation {
	readonly seq: number;
	readonly body: string;
	readonly signature: string;
	readonly result?: StepResult;
}

export type Completed =
	| {
			readonly kind: "completed";
			/** The completion, sealed to the screen's `eEnc`: HPKE's `enc` and ciphertext, base64url. */
			readonly enc: string;
			readonly ct: string;
			/** The id of the approval's record on the subject's flow: the reference its code's chain roots in. */
			readonly record: string;
			/** That record's reference on the log (`transparency-wire`'s `recordRef`), as an ID token's `apr` names it. */
			readonly ref: { readonly shard: string; readonly n: number };
			/** When the log accepted that record, in ms: an ID token's `auth_time`, in seconds. */
			readonly acceptedAt: number;
	  }
	| {
			readonly kind: "refused";
			readonly reason:
				| "unknown"
				| "purpose"
				| "unused"
				| "expired"
				| "code"
				| "key"
				| "ended"
				| "withdrawn";
	  };

/** Statements a person approves with a passkey, each signed, recorded, used once and answered. */
export interface Approvals {
	/** Signs a statement of `purpose` over its items, as the declared modules fill them, and records it. */
	issue(ask: IssueAsk): Promise<Issued>;
	/**
	 * Uses a statement once: an authorization's or a passkey-add's by an assertion over its challenge,
	 * its user verified; a possession's by the verification of its pending key. The same evidence again
	 * answers alike. A T whose sign-up began is used only once its key change kept the credential it
	 * registered, and only by an assertion of that credential (`used` otherwise).
	 */
	use(
		p: {
			readonly statement: string;
		} /** The assertion response's JSON text, as the screen sent it: its bytes are what is hashed. */ & (
			| { readonly assertion: string }
			| { readonly verification: string }
		),
	): Promise<Used>;
	/**
	 * A continuation the screen signed with its `eSig`: the next sequence number, once the last one's
	 * answer is kept, taken by one call, which runs `step` and keeps its answer on the record. The same
	 * continuation again answers what was kept, `pending` while a call holds its step, and runs `step`
	 * again only where the call that held it let its hold lapse: a step must take a second run alike.
	 * The step is handed the creation as its record keeps it, so its owner reads it from the record
	 * alone.
	 */
	continue(p: {
		readonly hash: string;
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
		readonly step: (kept: KeptCreation) => Promise<StepResult>;
	}): Promise<Continued>;
	/**
	 * A T's sign-up (F1), a continuation as `continue`'s, of continuation-wire's stage `sign-up`: number
	 * 1, the body `{}`, and a T whose owner allowed it, still issued and unexpired, checked in the write
	 * that takes it, which marks the T's sign-up begun. Its step is handed the T as its record keeps it,
	 * and answers a `SignUpResult`, kept and answered again alike.
	 */
	continueSignUp(p: {
		readonly hash: string;
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
		readonly step: (kept: KeptSignUp) => Promise<SignUpResult>;
	}): Promise<Continued>;
	/**
	 * Keeps the subject made for a T's begun sign-up, unless one is kept: the one kept is answered; none
	 * where no sign-up of it began.
	 */
	signUpSubject(hash: string, subject: string): Promise<string | undefined>;
	/**
	 * A T's sign-up as its record keeps it, while this generation's ring verifies its T; none for a T
	 * whose sign-up did not begin, or any other statement.
	 */
	signUpOf(hash: string): Promise<SignUp | undefined>;
	/**
	 * A creation's last continuation as taken, with what its step answered, from one read: while its
	 * statement lives and this generation's ring verifies it; none before one is taken, or for any
	 * other purpose.
	 */
	continuationOf(hash: string): Promise<LastContinuation | undefined>;
	/** An authorization's completion: its approval taken in on the subject's flow, then signed and sealed. */
	complete(p: { readonly hash: string; readonly code: string }): Promise<Completed>;
	/**
	 * A key change's completion, asked once its change took on the subject's flow (its caller's to
	 * know): the key its used possession names, signed and sealed to its screen, and kept on its
	 * record. Asked again for the same purpose, the one kept, with what the log gave as first asked;
	 * for another, `other`. The record lives a minute past the statement's expiry, `unknown` after.
	 * A sign-up's (F1) first keeps its credential on its T, unless the T kept another.
	 */
	completeKeyChange(ask: KeyChangeAsk): Promise<KeyChangeCompleted>;
	/**
	 * A passkey-add's completion, carrying the creation its caller made for it: signed and sealed to its
	 * screen, and kept on its record whole in one write, the first kept answered to every call after,
	 * whatever has lapsed since. One is made only for a used passkey-add unexpired that this
	 * generation's ring verifies, and a creation issued here for it.
	 */
	completePasskeyAdd(ask: PasskeyAddAsk): Promise<PasskeyAddCompleted>;
	/** A used statement's approval; none for any other. */
	usedOf(hash: string): Promise<Approval | undefined>;
	/**
	 * What a used authorization rests on, for a family rooted in it to check again (proposal 3.9): its
	 * statement as signed, the assertion's JSON text as received, and the credential that made it;
	 * none for any other statement, or once its record is gone.
	 */
	rootOf(
		hash: string,
	): Promise<
		| { readonly statement: string; readonly assertion: string; readonly credential: string }
		| undefined
	>;
	/**
	 * A used passkey-add, until its statement expires and while the Core's ring of this generation
	 * verifies it; none for any other statement, one not used, or one used before its key's
	 * registration was kept. The whole ceremony it approves lives within its statement's life.
	 */
	passkeyAddOf(hash: string): Promise<UsedPasskeyAdd | undefined>;
	/**
	 * A creation's record, whatever its continuations, until its statement expires and while the Core's
	 * ring of this generation verifies it; none for any other purpose. What its caller holds is its own
	 * to check against the creation.
	 */
	creationOf(hash: string): Promise<CreationRecord | undefined>;
	/**
	 * The completion kept for an authorization, as `complete` answered it, once its caller published
	 * it; none before.
	 */
	completionOf(hash: string): Promise<Extract<Completed, { kind: "completed" }> | undefined>;
	/**
	 * Marks the completion kept for an authorization as gone out, once its caller let it go (an
	 * authorization's code rooted first): `completionOf` gives it from then on. `published`, again for one published already; `unknown` where none is kept.
	 */
	publish(hash: string): Promise<"published" | "unknown">;
}

/** Taken only by a module that declares where it stands on the promises. */
export const approvals = contract<Approvals>("approvals", { takersContribute: stances });

/** The items of one purpose a module fills, by their names in sdk-core-wire's schema. */
export interface StatementItems {
	readonly purpose: Purpose;
	readonly names: readonly string[];
	readonly by: string;
}

/** Who fills which items: boot refuses a name the schema lacks, or one two modules fill. */
export const statementItems = extensionPoint<StatementItems>("approvals.statement-items", {
	multiplicity: "many",
});

declare const storedStatement: unique symbol;
/** A statement's record as kept: opaque to the store. */
export type StoredStatement = { readonly [storedStatement]: true };

/** Where statements' records are kept, by the statement's hash. Throws Unavailable when it cannot tell. */
export interface ApprovalStore {
	/** Keeps the record for its lifetime, unless one is kept already. */
	create(hash: string, record: StoredStatement, lifetimeMs: number): Promise<"created" | "exists">;
	read(hash: string): Promise<StoredStatement | undefined>;
	/** Changes the record from what it holds; `change` runs again on a lost race. None where none is kept. */
	change(
		hash: string,
		change: (
			current: StoredStatement,
		) => { readonly value: StoredStatement; readonly lifetimeMs?: number } | undefined,
	): Promise<{ readonly before: StoredStatement; readonly after: StoredStatement } | undefined>;
}

export const approvalStore = contract<ApprovalStore>("approvals.store");

/** What the statements' place must be, each a guarantee its wiring declares. */
export const approvalStoreNeeds = {
	/** A use lost to eviction or failover would let a statement be used twice. */
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** A stale read could answer a used statement as unused, or a continuation's sequence as free. */
	confirmedReads: true,
	/** A record written outside the provider would approve what no person approved. */
	authenticated: true,
} as const;

/** approvals' part of each subject's flow, which its wiring binds. */
export const approvalPart = part;
