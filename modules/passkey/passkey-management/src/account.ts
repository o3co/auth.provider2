import { createHash } from "node:crypto";
import type { Contact } from "@mod/users";

/** The identifier as a mail and a statement show it: its first character, and an address's domain. */
export function masked(identifier: string): string {
	const at = identifier.lastIndexOf("@");
	const first = [...identifier][0] ?? "";
	return at > 0 ? `${first}***${identifier.slice(at)}` : `${first}***`;
}

/** A short mark of a subject, six hex digits of its SHA-256: told apart in a list, never matched. */
const markOf = (subject: string) => createHash("sha256").update(subject).digest("hex").slice(0, 6);

/** An account no identifier names: the deployment's name and a short mark of its subject. */
export function nameOf(deployment: string, subject: string): string {
	return `${deployment} ${markOf(subject)}`;
}

/**
 * A subject's account where no identifier is asked: the address it verified last, masked; none
 * where it verified none, the creation then naming it by the deployment and a mark of its subject.
 */
export function accountOf(contacts: readonly Contact[]): { readonly account?: string } {
	const [last] = contacts;
	return last ? { account: masked(last.value) } : {};
}
