import type { SubjectOf } from "@mod/erasure-extensions";
import { deepFreeze } from "@mod/kernel";
import { canonicalAddress } from "@mod/mail-address";
import { type Contact, type Users, userAttribute } from "./contract.ts";
import { identifierFits, none, type UserSource, unanswerable } from "./registered.ts";
import type { ContactStore, StoredContacts } from "./store.ts";
import { keptFor } from "./stores/kept-for.ts";

const maxPasswordBytes = 1024;
const maxContacts = 20;

const isContact = (item: unknown): item is Contact =>
	(item as Contact | null)?.kind === "email" && typeof (item as Contact).value === "string";
const contactsIn = (record: StoredContacts | undefined): Contact[] =>
	(Array.isArray(record) ? record : [])
		.filter(isContact)
		.map(({ kind, value }) => ({ kind, value }));
const contactsRecord = (contacts: readonly Contact[]) => contacts as unknown as StoredContacts;

/** Whose a contacts record written before indexing is: the subject it is keyed by, where it holds a list. */
export const contactSubjectOf = (key: string, value: unknown): SubjectOf =>
	Array.isArray(value)
		? { kind: "subject", subject: key }
		: { kind: "unreadable", reason: "a contacts record of another shape" };

function required(...parts: string[]) {
	if (parts.some((part) => part === "")) throw new TypeError("users: an empty part names no one");
}

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

/** The source's users, with the contacts written through the store interface. */
export function ledgerUsers(source: UserSource, contacts: ContactStore): Users {
	return {
		verify: async (identifier, password) =>
			// The length is the sender's choice, so answering early tells nothing about users.
			Buffer.byteLength(password) > maxPasswordBytes || !identifierFits(identifier)
				? none
				: source.verify(identifier, password),
		bySubject: source.bySubject,
		...(source.byIdentifier ? { byIdentifier: fittingLookup(source.byIdentifier) } : {}),
		...(source.create ? { create: fitting(source.create) } : {}),
		verifiedContact: async (subject, contact) => {
			required(subject, contact.value);
			if (contact.kind !== "email") throw new TypeError("users: an unknown kind of contact");
			const kept = { kind: contact.kind, value: contact.value };
			// Compared in mail's one form, the domain's case aside; kept as first given.
			const sameAs = (value: string) => canonicalAddress(value) ?? value;
			const holds = (held: Contact[]) =>
				held.some((c) => c.kind === kept.kind && sameAs(c.value) === sameAs(kept.value));
			const add = (record: StoredContacts) => {
				const held = contactsIn(record);
				if (holds(held) || held.length >= maxContacts) return undefined;
				return { value: contactsRecord([...held, kept]) };
			};
			const { after } = await keptFor(contacts, subject, contactsRecord([kept]), add, subject);
			if (!holds(contactsIn(after))) {
				throw new RangeError(`users: a subject keeps at most ${maxContacts} contacts`);
			}
		},
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
