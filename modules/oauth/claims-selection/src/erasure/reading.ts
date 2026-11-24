import type { SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import type { StoredSelection } from "../store.ts";
import { kindOf, read } from "../stored.ts";

const unreadable = (reason: string): SubjectOf => ({ kind: "unreadable", reason });

/** Each kind's read. */
const readOf = { code: read.code, pin: read.pin, token: read.target };

/**
 * Whose a record is, as the migration reads it: its own subject, which every record keeps; a record
 * of another name or shape unreadable, never an orphan.
 */
export const selectionSubjectOf: SubjectReading = async (key, value) => {
	const named = kindOf(key);
	if (named === undefined) return unreadable("a record of no kind claims-selection names");
	try {
		return { kind: "subject", subject: readOf[named.kind](value as StoredSelection).subject };
	} catch {
		return unreadable("a record of another shape");
	}
};
