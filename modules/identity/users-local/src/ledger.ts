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

/**
 * The ledger over its records: a password checked by `checker`, which does the same work whether or
 * not the identifier holds a hash; a subject made for an identifier, drawn from `random`.
 */
export function localLedger(records: LocalRecords, checker: SecretChecker, random: Random): Ledger {
	return {
		verify: async (identifier, password) => {
			const held = await records.byIdentifier(identifier);
			const written = held?.["password-hash"];
			const hash = written === undefined ? undefined : readSecretHash(written);
			// A hash kept that secret-hash cannot read is a record of another shape, never no password.
			if (written !== undefined && hash === undefined) throw new Unavailable("users-local");
			const matched = await checker.check(hash, password);
			return held && hash && matched ? { kind: "user", user: userOf(held.subject) } : none;
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
			// A drawn subject held already: no answer for the identifier, which may be free.
			if (placed === "taken") throw new Unavailable("users-local");
			return placed === "placed" ? deepFreeze({ kind: "created", user: userOf(subject) }) : exists;
		},
		keep: async (subject, identifier) => {
			const placed = await records.place(identifier, subject);
			if (placed === "placed") return "kept";
			// Held as given, by an earlier import, is kept; held otherwise is a conflict.
			const held = placed === "exists" ? await records.byIdentifier(identifier) : undefined;
			return held?.subject === subject ? "kept" : "conflict";
		},
	};
}
