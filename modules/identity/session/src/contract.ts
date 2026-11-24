import { contract, extensionPoint } from "@mod/kernel";
import type { SourcedAttributes } from "@mod/login-attributes";

export interface AuthContext {
	readonly subject: string;
	readonly amr: readonly string[];
	/** Epoch ms; when the session opened if the authentication time is unknown. */
	readonly authenticatedAt: number;
	/** No login vouched for the authentication time: never count this session as freshly authenticated. */
	readonly authenticatedAtUnknown?: true;
	/** What the login said of the user, as it was at login. */
	readonly attributes?: SourcedAttributes;
}

export interface LoginFacts {
	readonly subject: string;
	readonly amr: readonly string[];
	/**
	 * When the user authenticated (epoch ms, 0 to 8.64e15), the opening when later; "opening", the session's
	 * opening, for a login the provider authenticates itself; or "unknown". Anything else is a TypeError.
	 */
	readonly authenticatedAt: number | "opening" | "unknown";
	readonly attributes?: SourcedAttributes;
	/**
	 * When the proof of this login began (epoch ms, 0 to 8.64e15), which only the login path knows:
	 * `open` refuses the login where its subject was revoked since. None, or anything else, is a TypeError.
	 */
	readonly provenSince: number;
	/**
	 * When the session ends (epoch ms, 0 to 8.64e15): the end of the delegation it carries, which the
	 * caller fixes. The session keeps it as given. None, or anything else, is a TypeError.
	 */
	readonly endsAt: number;
}

/** What `open` answers: the session opened, with its end, or none, its subject revoked since the proof began. */
export type Opened =
	| { readonly kind: "opened"; readonly session: Session; readonly endsAt: number }
	| { readonly kind: "revoked" };

export interface Session {
	readonly id: string;
	readonly context: AuthContext;
}

export type Entry =
	| { readonly kind: "entered"; readonly session: Session; readonly endsAt: number }
	| { readonly kind: "absent" };

/** What a close answers: closed, or pending while a participant has not finished. */
export interface CloseOutcome {
	readonly kind: "closed" | "pending";
	/** The session the close moved, by its handle and subject; none when no record was left to read. */
	readonly session?: { readonly id: string; readonly subject: string };
	/**
	 * The state the close found the record in, before it moved it: `open` (even one past its end),
	 * `closing` (a close left pending), or `closed`; none when no record was left to read.
	 */
	readonly from?: "open" | "closing" | "closed";
}

export interface Sessions {
	/**
	 * A new session under a new handle, at `kernel`'s time, telling it opened: its facts'
	 * `provenSince` is compared with the subject's revocation boundary once the session is saved and,
	 * revoked, the session is closed.
	 */
	open(facts: LoginFacts): Promise<Opened>;
	/** Closes the session in any state: closed, or pending (the session stays closing) until every participant has finished. */
	close(handle: string): Promise<CloseOutcome>;
	/** Entered with its end while the session is open, before its end and after its subject's revocation boundary; absent otherwise. */
	entryOf(handle: string): Promise<Entry>;
	/**
	 * The subject of the session's record under this handle, in any state, from one read: not an
	 * entry check. It writes nothing and checks no end or revocation. None where no record is, or it
	 * holds no subject; a record that cannot be read is Unavailable.
	 */
	subjectOf(handle: string): Promise<string | undefined>;
}

export const sessions = contract<Sessions>("session");

/** The one caller of a closing session's participants, contributed by the module that keeps them; its factory, and what it collects, take `sessions` only late. */
export interface ClosingParticipants {
	/** Calls each participant; answers each that failed, by name and the error's kind, none when all finished. */
	closing(
		session: Session,
	): Promise<readonly { readonly participant: string; readonly kind: string }[]>;
}

/** The one place an implementation calls the participants: at most one contribution. */
export const closingParticipants = extensionPoint<ClosingParticipants>(
	"session.closing-participants",
	{ multiplicity: "keyed", keyOf: () => "closing-participants" },
);

export { sessionRules } from "./rules/rules.ts";
