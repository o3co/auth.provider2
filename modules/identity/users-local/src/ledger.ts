import { deepFreeze, type Random, Unavailable } from "@mod/kernel";
import { readSecretHash, type SecretChecker } from "@mod/secret-hash";
import type { Created, Ledger, Verified } from "@mod/users";
import type { LocalRecords } from "./records/records.ts";

const none: Verified = deepFreeze({ kind: "none" });
const exists: Created = deepFreeze({ kind: "exists" });
/** A user of the ledger: its subject, holding no attributes. */
const userOf = (subject: string) => deepFreeze({ subject, attributes: {} });

/** The bytes of a new subject: drawn, so a subject tells nothing of its identifier. */
const subjectBytes = 16;

/** The passwords' checks: the checker over `password-work`, and that work's name. */
export interface Passwords {
	readonly checker: SecretChecker;
	readonly work: string;
}

/** The ledger over its records; a subject made for an identifier or an identifierless one for a key, drawn from `random`; passwords checked with `passwords`. */
export function localLedger(records: LocalRecords, random: Random, passwords: Passwords): Ledger {
	const { checker, work } = passwords;
	return {
		passwords: deepFreeze({ work }),
		verify: async (identifier, password) => {
			// One read and one computation of the work for every identifier, held, with no password, or not.
			const held = await records.byIdentifier(identifier);
			const stored = held?.passwordHash;
			const hash = stored === undefined ? undefined : readSecretHash(stored);
			// A hash it cannot read, or of another work, would be computed besides: none is checked.
			if (stored !== undefined && hash?.work !== work) throw new Unavailable("users-local");
			const matched = await checker.check(hash, password);
			return matched && held ? { kind: "user", user: userOf(held.subject) } : none;
		},
		bySubject: async (subject) =>
			(await records.bySubject(subject)) ? { kind: "user", user: userOf(subject) } : none,
		byIdentifier: async (identifier) => {
			const held = await records.byIdentifier(identifier);
			return held ? { kind: "user", user: userOf(held.subject) } : none;
		},
		create: async (identifier) => {
			const subject = Buffer.from(random.bytes(subjectBytes)).toString("hex");
			const placed = await records.place(identifier, subject);
			if (placed === "exists") return exists;
			// A drawn subject held already, or erased: no answer for the identifier, which may be free.
			if (placed !== "placed") throw new Unavailable("users-local");
			return deepFreeze({ kind: "created", user: userOf(subject) });
		},
		// The same key is answered the same subject: placed once, read back after, whoever placed it.
		createIdentifierless: async (key) => {
			const held = await records.byIdentifierlessKey(key);
			if (held) return userOf(held.subject);
			const subject = Buffer.from(random.bytes(subjectBytes)).toString("hex");
			const placed = await records.placeIdentifierless(key, subject);
			if (placed === "placed") return userOf(subject);
			// Placed at once by another: its subject is the key's.
			const after = placed === "exists" ? await records.byIdentifierlessKey(key) : undefined;
			// A drawn subject held already, or erased: no answer for the key, asked again.
			if (!after) throw new Unavailable("users-local");
			return userOf(after.subject);
		},
		keep: async (subject, identifier, passwordHash) => {
			if (passwordHash !== undefined && readSecretHash(passwordHash)?.work !== work) {
				throw new TypeError("users-local: a password's hash of another work than password-work");
			}
			const placed = await records.place(identifier, subject, passwordHash);
			if (placed === "placed") return "kept";
			// Held as given, by an earlier import, is kept; held otherwise, or erased, is a conflict.
			const held = placed === "exists" ? await records.byIdentifier(identifier) : undefined;
			const same = held?.subject === subject && held.passwordHash === passwordHash;
			return same ? "kept" : "conflict";
		},
	};
}
