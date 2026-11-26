import { deepFreeze } from "@mod/kernel";
import { contactsIn, keptContact } from "./contacts/contacts.ts";
import { type Users, userAttribute } from "./contract.ts";
import { identifierFits } from "./identifier/identifier.ts";
import { none, type UserSource, unanswerable } from "./registered.ts";
import type { ContactStore } from "./store.ts";

const maxPasswordBytes = 1024;

/** A lookup by identifier answering none past the bound, unasked. */
const fittingLookup =
	(lookup: NonNullable<UserSource["byIdentifier"]>): NonNullable<UserSource["byIdentifier"]> =>
	async (identifier) =>
		identifierFits(identifier) ? lookup(identifier) : none;

/** `create` refusing an identifier past the bound with a TypeError, unasked. */
const fitting =
	(create: NonNullable<UserSource["create"]>): NonNullable<UserSource["create"]> =>
	async (identifier) => {
		if (!identifierFits(identifier)) throw new TypeError("users: an identifier past its bound");
		return create(identifier);
	};

/** An identifierless subject's idempotency key: a SHA-256, base64url without padding. */
const identifierlessKey = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** `createIdentifierless` refusing a key of another form with a TypeError, unasked. */
const keyed =
	(
		create: NonNullable<UserSource["createIdentifierless"]>,
	): NonNullable<UserSource["createIdentifierless"]> =>
	async (key) => {
		if (typeof key !== "string" || !identifierlessKey.test(key))
			throw new TypeError("users: an identifierless subject's key is a SHA-256 in base64url");
		return create(key);
	};

/** The source's users, with the contacts written through the store interface. */
export function ledgerUsers(
	source: UserSource & Pick<Users, "verifyAsPart" | "failedChecks">,
	contacts: ContactStore,
): Users {
	// The length is the sender's choice, so answering early tells nothing about users.
	const unasked = (identifier: string, password: string) =>
		Buffer.byteLength(password) > maxPasswordBytes || !identifierFits(identifier);
	return {
		verify: async (identifier, password) =>
			unasked(identifier, password) ? none : source.verify(identifier, password),
		verifyAsPart: async (identifier, password) =>
			unasked(identifier, password)
				? { verified: none, settle: () => {} }
				: source.verifyAsPart(identifier, password),
		failedChecks: source.failedChecks,
		bySubject: source.bySubject,
		...(source.byIdentifier ? { byIdentifier: fittingLookup(source.byIdentifier) } : {}),
		...(source.create ? { create: fitting(source.create) } : {}),
		...(source.createIdentifierless
			? { createIdentifierless: keyed(source.createIdentifierless) }
			: {}),
		verifiedContact: keptContact(contacts, "verified"),
		contactsOf: async (subject) => deepFreeze(contactsIn(await contacts.read(subject))),
		claimedContacts: async (subject) => {
			const found = await source.bySubject(subject);
			if (found.kind === "unanswerable") return unanswerable;
			const email = found.kind === "user" ? found.user.attributes[userAttribute.email] : undefined;
			return deepFreeze(
				typeof email === "string" && email !== "" ? [{ kind: "email", value: email }] : [],
			);
		},
	};
}
