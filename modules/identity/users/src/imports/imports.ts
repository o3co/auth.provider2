import { isAddress } from "@mod/mail-address";
import {
	type ImportAnswer,
	isWellFormedSubject,
	type Users,
	type UsersImport,
} from "../contract.ts";
import { identifierFits, type UserSource } from "../registered.ts";

/** A record's keys: any other refuses it, so nothing brought is dropped unseen. */
const keys = new Set(["subject", "identifier", "verifiedEmail"]);

interface Read {
	readonly subject: string;
	readonly identifier?: string;
	readonly verifiedEmail?: string;
}

/** The record as read once, each part checked; undefined for any other shape. */
function readOf(given: unknown): Read | undefined {
	if (typeof given !== "object" || given === null || Array.isArray(given)) return undefined;
	const record = { ...(given as Record<string, unknown>) };
	if (Object.keys(record).some((key) => !keys.has(key))) return undefined;
	const { subject, identifier, verifiedEmail } = record;
	if (!isWellFormedSubject(subject)) return undefined;
	const named = typeof identifier === "string" && identifier !== "" && identifierFits(identifier);
	if (identifier !== undefined && !named) return undefined;
	if (verifiedEmail !== undefined && !isAddress(verifiedEmail)) return undefined;
	return {
		subject,
		...(identifier === undefined ? {} : { identifier: identifier as string }),
		...(verifiedEmail === undefined ? {} : { verifiedEmail: verifiedEmail as string }),
	};
}

/** Imports through the ledger's `keep`, where it has one, and users' verified contacts. */
export function usersImporter(users: Users, keep: UserSource["keep"]): UsersImport {
	return {
		record: async (given): Promise<ImportAnswer> => {
			const read = readOf(given);
			if (!read) return "malformed";
			if (read.identifier !== undefined) {
				if (!keep) return "outside";
				if ((await keep(read.subject, read.identifier)) === "conflict") return "conflict";
			}
			if (read.verifiedEmail !== undefined) {
				try {
					await users.verifiedContact(read.subject, { kind: "email", value: read.verifiedEmail });
				} catch (error) {
					// A subject past its contacts: the record is answered, never the run stopped.
					if (error instanceof RangeError) return "full";
					throw error;
				}
			}
			return "imported";
		},
	};
}
