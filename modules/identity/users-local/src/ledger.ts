import { deepFreeze, type Random, Unavailable } from "@mod/kernel";
import type { Created, Ledger, Verified } from "@mod/users";
import type { LocalRecords } from "./records/records.ts";

const none: Verified = deepFreeze({ kind: "none" });
const exists: Created = deepFreeze({ kind: "exists" });
/** A user of the ledger: its subject, holding no attributes. */
const userOf = (subject: string) => deepFreeze({ subject, attributes: {} });

/** The bytes of a new subject: drawn, so a subject tells nothing of its identifier. */
const subjectBytes = 16;

/** The ledger over its records, holding no password; a subject made for an identifier, drawn from `random`. */
export function localLedger(records: LocalRecords, random: Random): Ledger {
	return {
		// No password is held, so none matches, with the same work, none, for every identifier.
		verify: async () => none,
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
		keep: async (subject, identifier) => {
			const placed = await records.place(identifier, subject);
			if (placed === "placed") return "kept";
			// Held as given, by an earlier import, is kept; held otherwise, or erased, is a conflict.
			const held = placed === "exists" ? await records.byIdentifier(identifier) : undefined;
			return held?.subject === subject ? "kept" : "conflict";
		},
	};
}
