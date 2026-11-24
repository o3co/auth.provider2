import { deepFreeze } from "@mod/kernel";
import { readSecretHash, type SecretChecker, type SecretHash } from "@mod/secret-hash";
import { z } from "zod";
import {
	isAttributeValue,
	isWellFormedSubject,
	type Ledger,
	type Unanswerable,
	type User,
	type Users,
	userAttribute,
	type Verified,
} from "./contract.ts";

/** The longest identifier users takes, in UTF-8 bytes: a fixed guard on what is held and sent, past an email's 254. */
export const maxIdentifierBytes = 255;
/** Whether an identifier is within the bound; one past it is none, refused, or malformed, never asked for. */
export const identifierFits = (identifier: string) =>
	Buffer.byteLength(identifier) <= maxIdentifierBytes;

export const record = z
	.strictObject({
		identifier: z
			.string()
			.min(1)
			.refine(identifierFits, `at most ${maxIdentifierBytes} bytes`)
			.describe("What the user logs in with, matched exactly."),
		subject: z
			.string()
			.min(1)
			.optional()
			.describe("The subject, 1 to 255 ASCII characters; the identifier when left out."),
		"password-hash": z
			.string()
			.refine(
				(s) => readSecretHash(s) !== undefined,
				"a bcrypt or scrypt hash (plaintext is not accepted)",
			)
			.describe("The user's password as a bcrypt or scrypt hash."),
		attributes: z
			.record(z.string(), z.json())
			.superRefine((attributes, context) => {
				for (const [name, value] of Object.entries(attributes)) {
					if (isAttributeValue(name, value)) continue;
					context.addIssue({
						code: "custom",
						message: "not a value this attribute takes",
						path: [name],
					});
				}
				// An email's verification says nothing without the email, as a ledger's is left out; a
				// value it does not take is refused above already.
				const verified = attributes[userAttribute.emailVerified];
				if (typeof verified === "boolean" && !(userAttribute.email in attributes)) {
					context.addIssue({
						code: "custom",
						message: "only beside the user's email",
						path: [userAttribute.emailVerified],
					});
				}
			})
			.prefault({})
			.describe("The user's attributes by OIDC claim name, such as `email`, `name` or `groups`."),
	})
	.superRefine((user, context) => {
		// An empty one is refused at its own key already.
		const subject = user.subject ?? user.identifier;
		if (subject === "" || isWellFormedSubject(subject)) return;
		context.addIssue({
			code: "custom",
			message: "1 to 255 ASCII characters (the identifier's, where subject is left out)",
			path: ["subject"],
		});
	});

export const none: Verified = deepFreeze({ kind: "none" });
export const unanswerable: Unanswerable = deepFreeze({ kind: "unanswerable" });

/** Makes the checker for the hashes in use, as `secret-hash`'s checkers do; tests may record the work each check does. */
export type CheckerOf = (inUse: Iterable<SecretHash>) => SecretChecker;

export type UserSource = Pick<Users, "verify" | "bySubject" | "byIdentifier" | "create"> &
	Pick<Ledger, "keep">;

/** The users the settings register, checked by a checker `secret-hash` makes for their hashes. */
export function registeredUsers(
	registered: readonly z.output<typeof record>[],
	checkerOf: CheckerOf,
): UserSource {
	const known = new Map<string, { user: User; hash: SecretHash }>();
	const subjects = new Map<string, User>();
	for (const r of registered) {
		const user = deepFreeze({ subject: r.subject ?? r.identifier, attributes: r.attributes });
		// The section refused any other form at boot.
		known.set(r.identifier, { user, hash: readSecretHash(r["password-hash"]) as SecretHash });
		subjects.set(user.subject, user);
	}
	// An unknown identifier costs the same work as a known one: the checker computes decoys for it.
	const checker = checkerOf([...known.values()].map(({ hash }) => hash));
	return {
		verify: async (identifier, password) => {
			const found = known.get(identifier);
			const matched = await checker.check(found?.hash, password);
			return found && matched ? { kind: "user", user: found.user } : none;
		},
		byIdentifier: async (identifier) => {
			const found = known.get(identifier);
			return found ? { kind: "user", user: found.user } : none;
		},
		bySubject: async (subject) => {
			const user = subjects.get(subject);
			return user ? { kind: "user", user } : none;
		},
	};
}
