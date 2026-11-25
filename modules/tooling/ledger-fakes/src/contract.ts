import { randomBytes } from "node:crypto";
import { type LedgerUserAnswer, ledgerRoutes, usersWire, witnessWire } from "@mod/ledger-wire";

/** A call made to a fake ledger, as a fake HTTP server hands it on; header names lower case. */
export interface LedgerCall {
	readonly method: string;
	readonly path: string;
	readonly headers: Readonly<Record<string, string | undefined>>;
	readonly body: string;
}

/** A fake ledger's answer: a status, or a JSON body answered 200. */
export interface LedgerAnswer {
	readonly status?: number;
	readonly json?: unknown;
}

/** A user the fake user ledger holds: its password in the clear, as only a test holds one. */
export interface LedgerUser {
	readonly identifier: string;
	/** The password the password call checks; a user without one passes no password call. */
	readonly password?: string;
	/** The subject; the identifier when left out. */
	readonly subject?: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
}

/**
 * A fake ledger behind a credential of its own: its answer to a call (none for a call not its own;
 * a bare `404` for one of its own without the credential, so a wrong set-up shows), and where it
 * serves each call once it listens at `base`.
 */
export interface FakeLedger<Call extends string, Optional extends Call = never> {
	answer(call: LedgerCall): LedgerAnswer | undefined;
	/** Each call's URL; one of `Optional` is left out where the ledger has no route for it. */
	urls(
		base: string,
	): Readonly<Record<Exclude<Call, Optional>, string> & Partial<Record<Optional, string>>>;
	readonly credential: string;
}

type Routes = Readonly<Record<string, string>>;

/** Each route at `base`, keyed by its call. */
const at = <R extends Routes>(routes: R, base: string) =>
	Object.fromEntries(Object.entries(routes).map(([name, path]) => [name, `${base}${path}`])) as {
		readonly [K in keyof R]: string;
	};

/** Whether a call is one of the routes, and whether it carries the credential, by POST. */
const ownCall = (routes: Routes, call: LedgerCall) => Object.values(routes).includes(call.path);
const authorized = (credential: string, call: LedgerCall) =>
	call.method === "POST" && call.headers.authorization === `Bearer ${credential}`;

/**
 * A fake user ledger holding these users, as users-http calls it: the password call, the lookups by
 * subject and by identifier, the create, which adds a user with no password under a subject drawn
 * for it, and the identifierless create, which draws a subject for a key once and answers it for that key
 * ever after.
 */
export function usersLedger(
	users: readonly LedgerUser[],
): FakeLedger<keyof typeof ledgerRoutes.users> {
	const routes = ledgerRoutes.users;
	const credential = randomBytes(32).toString("hex");
	const held: LedgerUser[] = [...users];
	/** The subject each identifierless create's key was answered. */
	const identifierless = new Map<string, string>();
	const answerOf = (user: LedgerUser): LedgerUserAnswer => ({
		id: user.subject ?? user.identifier,
		username: user.identifier,
		...(user.email === undefined ? {} : { email: user.email }),
		...(user.emailVerified === undefined ? {} : { emailVerified: user.emailVerified }),
		...(user.name === undefined ? {} : { name: user.name }),
	});
	const noUser = { status: 404, json: { error: usersWire.noUser[404] } };
	return {
		credential,
		urls: (base) => at(routes, base),
		answer(call) {
			if (!ownCall(routes, call)) return undefined;
			if (!authorized(credential, call)) return { status: 404 };
			// The bodies users-http sends, as the wire builds them.
			const given = JSON.parse(call.body) as Partial<
				ReturnType<typeof usersWire.verify> &
					ReturnType<typeof usersWire.bySubject> &
					ReturnType<typeof usersWire.createIdentifierless>
			>;
			if (call.path === routes.createIdentifierless) {
				const { key } = given;
				if (!usersWire.identifierlessKey.safeParse(key).success) return { status: 400 };
				const subject = identifierless.get(String(key)) ?? randomBytes(16).toString("hex");
				identifierless.set(String(key), subject);
				return { status: usersWire.created, json: { id: subject } };
			}
			const byIdentifier = held.find((u) => u.identifier === given.email);
			if (call.path === routes.create) {
				if (byIdentifier) return { status: 409, json: { error: usersWire.taken[409] } };
				const made: LedgerUser = {
					identifier: String(given.email),
					subject: randomBytes(16).toString("hex"),
				};
				held.push(made);
				return { status: usersWire.created, json: answerOf(made) };
			}
			// An identifierless subject is found by its subject alone: it has no identifier.
			if (
				call.path === routes.subject &&
				[...identifierless.values()].includes(String(given.subject))
			)
				return { json: { id: String(given.subject) } };
			const user =
				call.path === routes.subject
					? held.find((u) => (u.subject ?? u.identifier) === given.subject)
					: call.path === routes.identifier
						? byIdentifier
						: byIdentifier?.password !== undefined && byIdentifier.password === given.password
							? byIdentifier
							: undefined;
			// A lookup says it knows no such user; a bare 404 above is a wrong set-up.
			return user ? { json: answerOf(user) } : noUser;
		},
	};
}

/** The marks a witness ledger keeps: one per subject, set only where none is, withdrawn only by its token. */
function marksKept() {
	const marks = new Map<string, string>();
	return {
		mark: (subject: string) => marks.get(subject),
		enroll(subject: string, token: string) {
			if (!marks.has(subject)) marks.set(subject, token);
			return { owner: marks.get(subject) === token };
		},
		// One row per subject: a withdraw compares the token and deletes on that row alone.
		withdraw(subject: string, token: string) {
			if (marks.get(subject) === token) marks.delete(subject);
		},
	};
}

/** A witness's read: whether the subject is marked, naming the mark's token. */
const markRead = (mark: string | undefined) =>
	mark === undefined ? { enrolled: false } : { enrolled: true, token: mark };

/** A witness ledger's answer to one of its calls, given the routes it keeps. */
function witnessAnswer(
	routes: Routes,
	kept: ReturnType<typeof marksKept>,
	call: LedgerCall,
): LedgerAnswer {
	const given = JSON.parse(call.body) as Partial<ReturnType<typeof witnessWire.withdraw>>;
	const subject = String(given.subject);
	if (call.path === routes.read) return { json: markRead(kept.mark(subject)) };
	if (call.path === routes.enroll) return { json: kept.enroll(subject, String(given.token)) };
	kept.withdraw(subject, String(given.token));
	return { status: witnessWire.written };
}

/** A fake ledger keeping the passkey witness: a read names the mark's token, and no clear is its call. */
export function passkeyWitnessLedger(): FakeLedger<keyof typeof ledgerRoutes.passkeyWitness> {
	const routes = ledgerRoutes.passkeyWitness;
	const credential = randomBytes(32).toString("base64url");
	const kept = marksKept();
	return {
		credential,
		urls: (base) => at(routes, base),
		answer(call) {
			if (!ownCall(routes, call)) return undefined;
			if (!authorized(credential, call)) return { status: 404 };
			return witnessAnswer(routes, kept, call);
		},
	};
}
