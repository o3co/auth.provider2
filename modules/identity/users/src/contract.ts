import { contract, extensionPoint } from "@mod/kernel";
import { isAddress } from "@mod/mail-address";

export interface User {
	readonly subject: string;
	/** Read once and frozen. */
	readonly attributes: Readonly<Record<string, unknown>>;
}

/** The names of the attributes users knows: their OIDC claim names, typed below; a user may hold others. */
export const userAttribute = Object.freeze({
	email: "email",
	emailVerified: "email_verified",
	name: "name",
	picture: "picture",
	groups: "groups",
} as const);

export interface UserAttributes {
	readonly [userAttribute.email]?: string;
	readonly [userAttribute.emailVerified]?: boolean;
	readonly [userAttribute.name]?: string;
	readonly [userAttribute.picture]?: string;
	readonly [userAttribute.groups]?: readonly string[];
}

/** Text with no control or format character, bidi controls among them. */
const isPlainText = (value: unknown): value is string =>
	typeof value === "string" && !/[\p{Cc}\p{Cf}]/u.test(value);

/** Plain text that holds more than blanks, so a claim drawn from it is never empty. */
const isNamedText = (value: unknown): value is string => isPlainText(value) && /\S/u.test(value);

/** RFC 5322's atext: the ASCII letters, digits and the marks a dot-atom may hold. */
const atext = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+";
/** An LDH label of at most 63 characters, neither starting nor ending with a hyphen. */
const ldhLabel = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
/** RFC 5322's addr-spec in ASCII: a dot-atom local part, at a domain of LDH labels. */
const addrSpec = new RegExp(`^${atext}(?:\\.${atext})*@${ldhLabel}(?:\\.${ldhLabel})*$`);

/** An address mail takes that is also RFC 5322's addr-spec, as an `email` claim must be (OpenID Connect Core §5.1). */
const isEmailClaim = (value: unknown): value is string => isAddress(value) && addrSpec.test(value);

/** An https URL that reads back as given: no blank character, and its parsed form unchanged. */
function isPictureUrl(value: unknown): boolean {
	if (!isPlainText(value) || /\s/u.test(value)) return false;
	const url = URL.parse(value);
	return url?.protocol === "https:" && url.href === value;
}

const attributeRules = new Map<string, (value: unknown) => boolean>([
	[userAttribute.email, isEmailClaim],
	[userAttribute.emailVerified, (value) => typeof value === "boolean"],
	[userAttribute.name, isNamedText],
	[userAttribute.picture, isPictureUrl],
	[userAttribute.groups, (value) => Array.isArray(value) && value.every(isPlainText)],
]);

/** Whether `value` is a form users accepts for the attribute `name`; another name takes any value, a string only as plain text. */
export const isAttributeValue = (name: string, value: unknown): boolean =>
	(attributeRules.get(name) ?? ((other) => typeof other !== "string" || isPlainText(other)))(value);

/**
 * From values of any shape, the attributes users names, each in a form it accepts, frozen; an
 * email's verification only beside the email. Any other name or form is left out.
 */
export function acceptedAttributes(values: unknown): UserAttributes {
	if (typeof values !== "object" || values === null || Array.isArray(values))
		return Object.freeze({});
	const given = values as Record<string, unknown>;
	// Each value is read once, and a list copied before it is judged, so what is judged is what is kept.
	const at = (name: string) => {
		const read = given[name];
		const value = Array.isArray(read) ? [...read] : read;
		return isAttributeValue(name, value) ? value : undefined;
	};
	const email = at(userAttribute.email) as string | undefined;
	const verified =
		email === undefined ? undefined : (at(userAttribute.emailVerified) as boolean | undefined);
	const name = at(userAttribute.name) as string | undefined;
	const picture = at(userAttribute.picture) as string | undefined;
	const groups = at(userAttribute.groups) as readonly string[] | undefined;
	return Object.freeze({
		...(email === undefined ? {} : { [userAttribute.email]: email }),
		...(verified === undefined ? {} : { [userAttribute.emailVerified]: verified }),
		...(name === undefined ? {} : { [userAttribute.name]: name }),
		...(picture === undefined ? {} : { [userAttribute.picture]: picture }),
		...(groups === undefined ? {} : { [userAttribute.groups]: Object.freeze(groups) }),
	});
}

/** A subject's shape, as OpenID Connect Core §2 bounds `sub`: 1 to 255 ASCII characters. */
export const isWellFormedSubject = (value: unknown): value is string =>
	typeof value === "string" && /^\p{ASCII}{1,255}$/u.test(value);

export type Verified = { readonly kind: "user"; readonly user: User } | { readonly kind: "none" };
/** What the user ledger answers when it cannot look users up by subject; never read as none. */
export type Unanswerable = { readonly kind: "unanswerable" };
export type BySubject = Verified | Unanswerable;
/** A new subject made for an identifier, or `exists` where a user holds the identifier already. */
export type Created =
	| { readonly kind: "created"; readonly user: User }
	| { readonly kind: "exists" };

export interface Contact {
	readonly kind: "email";
	readonly value: string;
}

export interface Users {
	/**
	 * Takes the same work whether or not the user exists; throws Unavailable if the ledger fails, or
	 * where the identifier's checks are queued past their bound.
	 */
	verify(identifier: string, password: string): Promise<Verified>;
	bySubject(subject: string): Promise<BySubject>;
	/**
	 * The user holding the identifier, matched exactly; none for an empty one. Offered where the
	 * settings hold the users or the ledger looks users up by identifier: its absence is the
	 * composition's fact. Throws Unavailable if the ledger fails.
	 */
	byIdentifier?(identifier: string): Promise<Verified>;
	/**
	 * Makes a new subject for the identifier, offered where the ledger makes subjects: its absence is
	 * the composition's fact. Throws TypeError on an empty identifier, Unavailable if the ledger fails.
	 */
	create?(identifier: string): Promise<Created>;
	/** Keeps a contact the subject has shown is theirs, up to 20. Throws TypeError on an empty part, RangeError past 20. */
	verifiedContact(subject: string, contact: Contact): Promise<void>;
	/** The subject's verified contacts, in the order first kept, frozen. */
	contactsOf(subject: string): Promise<readonly Contact[]>;
	/** Contacts the settings or the ledger state for the subject, not shown to be theirs; frozen, or unanswerable. */
	claimedContacts(subject: string): Promise<readonly Contact[] | Unanswerable>;
}

/** What importing one record answers: `usersImport`'s words. */
export type ImportAnswer = "imported" | "conflict" | "outside" | "malformed" | "full";

/** Records brought from another IdP, as an import entry hands them over one at a time. */
export interface UsersImport {
	/**
	 * Keeps `{ subject, identifier?, passwordHash?, verifiedEmail? }`: the identifier, with the
	 * password's hash where given, through the ledger's `keep`, then the email as a verified contact.
	 * `imported` once every part is held as given, now or before; `conflict` where the ledger holds
	 * the identifier or the subject otherwise, `outside` where an identifier is given and the ledger
	 * takes no import, or a hash and it holds no passwords of its work, `malformed` for any other shape (another
	 * key, a hash with no identifier or one `secret-hash` does not read, among them), each writing
	 * nothing; `full` past a subject's contacts. Throws Unavailable if the ledger or the store fails.
	 */
	record(record: unknown): Promise<ImportAnswer>;
}

export interface Ledger {
	/** None when no user matches, after the same work as for a known identifier; throws Unavailable when the ledger fails or refuses. */
	verify(identifier: string, password: string): Promise<Verified>;
	bySubject(subject: string): Promise<BySubject>;
	/** None when no user holds the identifier; throws Unavailable when the ledger fails or refuses. A ledger that looks no one up by identifier leaves it out. */
	byIdentifier?(identifier: string): Promise<Verified>;
	/** Makes a new subject for an identifier no user holds, else `exists`; a ledger that makes no subjects leaves it out. */
	create?(identifier: string): Promise<Created>;
	/**
	 * Holds the identifier for the subject as given, written now or before (`kept`), unless either is
	 * held otherwise (`conflict`); a ledger that takes no import leaves it out. A password's hash, as
	 * `secret-hash` reads one, is given only to a ledger that holds passwords, for the identifier.
	 */
	keep?(subject: string, identifier: string, passwordHash?: string): Promise<"kept" | "conflict">;
	/**
	 * The work (`secret-hash`'s word) of the passwords' hashes its `keep` takes, which `verify` checks
	 * them at. A ledger whose `keep` takes none, or with no `keep`, leaves it out, whether or not it
	 * checks passwords: it says nothing of whether a deployment holds them.
	 */
	readonly passwords?: { readonly work: string };
}

export const users = contract<Users>("users");
export const usersImport = contract<UsersImport>("users.import");
export const ledgers = extensionPoint<Ledger>("users.ledgers", { multiplicity: "many" });
export * from "./store.ts";
