import { createHash } from "node:crypto";
import type { Contact } from "@mod/users";

/** The identifier as a mail and a statement show it: its first character, and an address's domain. */
export function masked(identifier: string): string {
	const at = identifier.lastIndexOf("@");
	const first = [...identifier][0] ?? "";
	return at > 0 ? `${first}***${identifier.slice(at)}` : `${first}***`;
}

/** The deployment's name an account no address names shows: `account-name`, else the mail link's host, as long as it may be. */
export const deploymentOf = (s: {
	readonly "account-name"?: string | undefined;
	readonly "mail-link": string;
}) => s["account-name"] ?? new URL(s["mail-link"]).hostname.slice(0, 50);

/** A short mark of a subject, six hex digits of its SHA-256: told apart in a list, never matched. */
const markOf = (subject: string) => createHash("sha256").update(subject).digest("hex").slice(0, 6);

/** An account no identifier names: the deployment's name and a short mark of its subject. */
export function nameOf(deployment: string, subject: string): string {
	return `${deployment} ${markOf(subject)}`;
}

/** How a creation shows its account: an identifier or address masked, or a name no identifier gives. */
export type Shown =
	| { readonly account: string; readonly userName?: never }
	| { readonly userName: string; readonly account?: never };

/**
 * A subject's account where no identifier is asked: the address it verified last, masked, as its
 * `account`; one with none verified, the deployment's name and a short mark of its subject, as its
 * `userName`, as F1's is.
 */
export function accountOf(
	contacts: readonly Contact[],
	deployment: string,
	subject: string,
): Shown {
	const [last] = contacts;
	return last ? { account: masked(last.value) } : { userName: nameOf(deployment, subject) };
}
