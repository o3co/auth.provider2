import type { SubjectOf } from "@mod/erasure-extensions";
import { canonicalAddress, isAddress } from "@mod/mail-address";
import type { Contact } from "../contract.ts";
import type { ContactStore, StoredContacts } from "../store.ts";
import { keptFor } from "../stores/kept-for.ts";

/** The most contacts a subject keeps. */
const maxContacts = 20;

/**
 * A contact users keeps: an email address mail takes (mail-address's `isAddress`: 254 bytes at most, no
 * blank, quote, backslash or control character, an internationalized one taken). A passkey's creation
 * shows it masked as the account, so its form bounds that statement's size; one stored otherwise is not read.
 */
const isContact = (item: unknown): item is Contact =>
	(item as Contact | null)?.kind === "email" && isAddress((item as Contact).value);
/** The contacts a stored record holds, each in its form: one stored otherwise is not read. */
export const contactsIn = (record: StoredContacts | undefined): Contact[] =>
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

/**
 * Keeps a contact for the subject, up to `maxContacts`, compared in mail's one form and kept as first
 * given. Verified here, it comes first, one held moving there; brought from another IdP, a new one is
 * added last and one held stays where it is, as that IdP verified it before any verified here.
 */
export function keptContact(contacts: ContactStore, how: "verified" | "brought") {
	return async (subject: string, contact: Contact): Promise<void> => {
		required(subject, contact.value);
		if (contact.kind !== "email") throw new TypeError("users: an unknown kind of contact");
		if (!isContact(contact)) throw new TypeError("users: an address mail does not take");
		const kept = { kind: contact.kind, value: contact.value };
		const sameAs = (value: string) => canonicalAddress(value) ?? value;
		const isKept = (c: Contact) => c.kind === kept.kind && sameAs(c.value) === sameAs(kept.value);
		const holds = (held: Contact[]) => held.some(isKept);
		const add = (record: StoredContacts) => {
			const held = contactsIn(record);
			const at = held.findIndex(isKept);
			if (at === 0 || (at > 0 && how === "brought")) return undefined;
			if (at > 0) return { value: contactsRecord([held[at] as Contact, ...held.toSpliced(at, 1)]) };
			if (held.length >= maxContacts) return undefined;
			return { value: contactsRecord(how === "verified" ? [kept, ...held] : [...held, kept]) };
		};
		const { after } = await keptFor(contacts, subject, contactsRecord([kept]), add, subject);
		if (!holds(contactsIn(after))) {
			throw new RangeError(`users: a subject keeps at most ${maxContacts} contacts`);
		}
	};
}
