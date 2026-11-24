import { extensionPoint } from "@mod/kernel";

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
