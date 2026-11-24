import type { Eraser, SubjectOf, SubjectReading } from "@mod/erasure-extensions";
import { kindOf, read } from "../record.ts";
import type { FamilyRecords, StoredFamilyRecord } from "../store.ts";

/** Why the store's set of ports cannot be used, or none: `erase` and `migrate` together, or neither. */
export function portsRefused(records: FamilyRecords): string | undefined {
	return (records.erase === undefined) !== (records.migrate === undefined)
		? "refresh's store offers part of its erase and migrate: both, or neither"
		: undefined;
}

const unreadable = (reason: string): SubjectOf => ({ kind: "unreadable", reason });

/**
 * Whose a record is, as the migration reads it: its own subject, which every record keeps; a record
 * of another name or shape unreadable, never an orphan.
 */
export const familySubjectOf: SubjectReading = async (key, value) => {
	const named = kindOf(key);
	if (named === undefined) return unreadable("a record of no kind refresh names");
	try {
		const r = read[named.kind](value as StoredFamilyRecord);
		return r ? { kind: "subject", subject: r.subject } : unreadable("a record of no value");
	} catch {
		return unreadable("a record of another shape");
	}
};

/**
 * refresh's eraser, `refresh`, as its space's `erasedBy` names it: a subject's families, keys and
 * codes erased through the store's own ports; `erasable` only where the store offers both.
 */
export function familyEraser(records: FamilyRecords): Eraser {
	const { erase, migrate } = records;
	if (!erase || !migrate) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "refresh",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await erase.call(records, subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "refresh",
		erasable: true,
		online,
		// Records are indexed by their subject: no walk reaches more, so a window erases each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => [await migrate.call(records, walk, familySubjectOf, signal)],
	};
}
