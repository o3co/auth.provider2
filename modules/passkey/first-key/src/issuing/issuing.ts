import type { BuildContext } from "@mod/kernel";
import type { Mail } from "@mod/mail";
import { mail } from "@mod/mail";
import { masked } from "@mod/passkey-management";
import type { Held, Passkeys } from "@mod/passkeys";
import { heldKeys, passkeys } from "@mod/passkeys";
import type { Contact, Users } from "@mod/users";
import { users } from "@mod/users";
import { firstKeyMail } from "../contract.ts";
import type { Settings } from "../section.ts";
import type { IssuedToken } from "../tokens/tokens.ts";

/** A start that passed, as its job is given it: the subject, the identifier asked, the code its screen shows, when it began. */
export interface Passed {
	readonly subject: string;
	readonly identifier: string;
	readonly code: string;
	/** Kernel clock ms: where its evidence began, which the token keeps. */
	readonly startedAt: number;
}

/** What one job did, for the path to write down: never the address. */
export type Issued = "sent" | "holds" | "unreachable" | "limited";

/**
 * Where a first key's mail goes (§3.13): the contact users verified last; else the `email` its one
 * read by subject answers with `email_verified` true; else none.
 */
async function recipientOf(
	users: Pick<Users, "contactsOf" | "bySubject">,
	subject: string,
): Promise<string | undefined> {
	const [verified] = (await users.contactsOf(subject)).filter((c: Contact) => c.kind === "email");
	if (verified) return verified.value;
	const read = await users.bySubject(subject);
	if (read.kind !== "user") return undefined;
	const { email, email_verified: confirmed } = read.user.attributes;
	return typeof email === "string" && confirmed === true ? email : undefined;
}

/**
 * The job of a start that passed: off the start's answer, so its work never tells whether a key is
 * held or a mail sent. It settles the subject's keys, so a mark a boundary left is withdrawn; where it
 * holds none, picks the address, writes the token, and only once it is written sends the mail.
 */
export function issuingOver(p: {
	readonly passkeys: Pick<Passkeys, "settle">;
	readonly held: { of(subject: string): Promise<Held> };
	readonly users: Pick<Users, "contactsOf" | "bySubject">;
	readonly issue: (subject: string, code: string, since: number) => Promise<IssuedToken>;
	readonly mail: Mail;
	readonly link: string;
	readonly lifetimeMs: number;
}) {
	return async (passed: Passed): Promise<Issued> => {
		// From the applied state alone, idempotent: it brings the witness's mark and the removals' notices
		// in line, so anyone who can start may cause it. A mark left after it holds, as a reservation reads it.
		const holds = await p.passkeys.settle(passed.subject);
		if (holds || (await p.held.of(passed.subject)).marked) return "holds";
		const to = await recipientOf(p.users, passed.subject);
		// No address: no token either, so none is left unusable in the store.
		if (to === undefined) return "unreachable";
		const { token, until } = await p.issue(passed.subject, passed.code, passed.startedAt);
		const { link, account, minutes } = firstKeyMail.values;
		const sent = await p.mail.send({
			purpose: firstKeyMail.purpose,
			to,
			values: {
				[link]: `${p.link}#${token}`,
				[account]: masked(passed.identifier),
				[minutes]: String(Math.round(p.lifetimeMs / 60_000)),
			},
			expiresAt: until,
		});
		return sent === "sent" ? "sent" : "limited";
	};
}

/** What the issuing takes in a build, which the path names among its takes. */
export const issuingTakes = [passkeys, heldKeys, users, mail] as const;

/** A start's issuing made in a build, over the tokens' `issue`: passkeys, users and mail its own to take. */
export async function issuingOf(
	c: BuildContext<Settings>,
	issue: Parameters<typeof issuingOver>[0]["issue"],
) {
	return issuingOver({
		passkeys: await c.get(passkeys),
		held: await c.get(heldKeys),
		users: await c.get(users),
		issue,
		mail: await c.get(mail),
		link: c.section["mail-link"],
		lifetimeMs: c.section["token-lifetime"] * 1000,
	});
}
