import { z } from "zod";

/** A user as the user ledger answers it: `200` to the password call and to a lookup, `201` to a create. */
export interface LedgerUserAnswer {
	/** The subject. */
	readonly id: string;
	/** The identifier the password call checked; its answer names it. */
	readonly username?: string;
	readonly email?: string;
	/** Whether `email` is verified; said beside it alone. */
	readonly emailVerified?: boolean;
	readonly name?: string;
	readonly picture?: string;
	readonly groups?: readonly string[];
}

/** The user ledger's calls, as users-http makes them and a ledger answers them. */
export const usersWire = Object.freeze({
	/** The password call's body: the identifier under the name the ledger reads. */
	verify: (identifier: string, password: string) => ({ email: identifier, password }),
	/** A lookup's body, by subject. */
	bySubject: (subject: string) => ({ subject }),
	/** A lookup's body, by identifier, under the name the password call gives it. */
	byIdentifier: (identifier: string) => ({ email: identifier }),
	/** A create's body: the identifier a new subject is made for. */
	create: (identifier: string) => ({ email: identifier }),
	/**
	 * An identifierless create's body: a new subject made for no identifier, under an idempotency key (a
	 * SHA-256, base64url) the caller derives from what the subject is made for. The same key is
	 * answered the same subject, however often and however many at once: a create whose answer was
	 * lost is asked again and makes no second subject.
	 */
	createIdentifierless: (key: string) => ({ key }),
	/** An identifierless create's key: a SHA-256, base64url without padding. */
	identifierlessKey: z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/),
	/** A create's answer, with the user made (an identifierless create's: the subject its key names, made now or before). */
	created: 201,
	/** What a create's `409` says in `error` to mean the identifier has a subject already; unsaid, it means nothing. */
	taken: Object.freeze({ 409: "exists" }) as Readonly<Record<number, string>>,
	/** What a lookup's or the password call's `404` and `410` say in `error` to mean no such user; unsaid, they mean nothing. */
	noUser: Object.freeze({ 404: "not_found", 410: "gone" }) as Readonly<Record<number, string>>,
});

/** A witness ledger's calls, as passkey-witness-http makes them: their bodies and answers. */
export const witnessWire = Object.freeze({
	read: (subject: string) => ({ subject }),
	/** A write's `deadline`: the time (ms since the epoch) past which the provider no longer waits for it. */
	enroll: (subject: string, token: string, deadline: number) => ({ subject, token, deadline }),
	withdraw: (subject: string, token: string, deadline: number) => ({ subject, token, deadline }),
	clear: (subject: string, deadline: number) => ({ subject, deadline }),
	/** A read's answer: whether the subject is marked. */
	readAnswer: z.object({ enrolled: z.boolean() }),
	/** A read's answer where withdraw is offered: a marked one names its mark's token. */
	markAnswer: z.union([
		z.object({ enrolled: z.literal(true), token: z.string().min(1) }),
		z.object({ enrolled: z.literal(false) }),
	]),
	/** An enroll's answer: whether the token sent is the mark's, set now or before. */
	enrollAnswer: z.object({ owner: z.boolean() }),
	/** A write's answer (withdraw, clear) once done. */
	written: 204,
});

/** The routes a fake ledger and the examples serve each call at; a deployment's are its settings' URLs. */
export const ledgerRoutes = Object.freeze({
	users: Object.freeze({
		verify: "/verify",
		subject: "/subject",
		identifier: "/identifier",
		create: "/create",
		createIdentifierless: "/create-identifierless",
	}),
	passkeyWitness: Object.freeze({
		read: "/passkey-witness/read",
		enroll: "/passkey-witness/enroll",
		withdraw: "/passkey-witness/withdraw",
	}),
});
