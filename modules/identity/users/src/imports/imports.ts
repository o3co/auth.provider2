import { isAddress } from "@mod/mail-address";
import { readSecretHash } from "@mod/secret-hash";
import {
	type Contact,
	type ImportAnswer,
	isWellFormedSubject,
	type UsersImport,
} from "../contract.ts";
import { identifierFits } from "../identifier/identifier.ts";
import type { UserSource } from "../registered.ts";

/** A record's keys: any other refuses it, so nothing brought is dropped unseen. */
const keys = new Set(["subject", "identifier", "passwordHash", "verifiedEmail"]);

interface Read {
	readonly subject: string;
	readonly identifier?: string;
	/** The password's hash as brought, and its work as `secret-hash` reads it. */
	readonly password?: { readonly hash: string; readonly work: string };
	readonly verifiedEmail?: string;
}

/** The record as read once, each part checked; undefined for any other shape. */
function readOf(given: unknown): Read | undefined {
	if (typeof given !== "object" || given === null || Array.isArray(given)) return undefined;
	const record = { ...(given as Record<string, unknown>) };
	if (Object.keys(record).some((key) => !keys.has(key))) return undefined;
	const { subject, identifier, passwordHash, verifiedEmail } = record;
	if (!isWellFormedSubject(subject)) return undefined;
	const named = typeof identifier === "string" && identifier !== "" && identifierFits(identifier);
	if (identifier !== undefined && !named) return undefined;
	// A password's hash goes with the identifier it is checked for, and is one `secret-hash` reads.
	const hashed = typeof passwordHash === "string" ? readSecretHash(passwordHash) : undefined;
	if (passwordHash !== undefined && (!hashed || identifier === undefined)) return undefined;
	if (verifiedEmail !== undefined && !isAddress(verifiedEmail)) return undefined;
	return {
		subject,
		...(identifier === undefined ? {} : { identifier: identifier as string }),
		...(hashed ? { password: { hash: passwordHash as string, work: hashed.work } } : {}),
		...(verifiedEmail === undefined ? {} : { verifiedEmail: verifiedEmail as string }),
	};
}

/** Imports through the ledger's `keep`, where it has one, and users' verified contacts, as brought. */
export function usersImporter(
	keep: UserSource["keep"],
	passwordWork: string | undefined,
	/** Keeps a contact brought from another IdP, which moves none held. */
	brought: (subject: string, contact: Contact) => Promise<void>,
): UsersImport {
	return {
		record: async (given): Promise<ImportAnswer> => {
			const read = readOf(given);
			if (!read) return "malformed";
			if (read.identifier !== undefined) {
				// A hash goes only to a ledger whose `keep` takes hashes of its work.
				const taken = read.password === undefined || read.password.work === passwordWork;
				if (!keep || !taken) return "outside";
				const kept =
					read.password === undefined
						? await keep(read.subject, read.identifier)
						: await keep(read.subject, read.identifier, read.password.hash);
				if (kept === "conflict") return "conflict";
			}
			if (read.verifiedEmail !== undefined) {
				try {
					await brought(read.subject, { kind: "email", value: read.verifiedEmail });
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
