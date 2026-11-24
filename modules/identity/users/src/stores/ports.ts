import type { ContactStore } from "../store.ts";

/**
 * Why the contact store's ports cannot be used together, or none. The one statement of the set: its
 * `erase` and `migrate` together or neither. A part of it would leave records users cannot erase or
 * index.
 */
export function portsRefused(contacts: ContactStore): string | undefined {
	if ((contacts.erase === undefined) !== (contacts.migrate === undefined)) {
		return "the contact store offers one of erase and migrate: it offers both, or neither";
	}
	return undefined;
}

/** Whether the store offers its set whole, as users' eraser needs to erase: none refused, none missing. */
export const everyPortOffered = (contacts: ContactStore): boolean =>
	portsRefused(contacts) === undefined && contacts.erase !== undefined;
