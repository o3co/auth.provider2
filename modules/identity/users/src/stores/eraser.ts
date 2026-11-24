import type { Eraser, MigrationReport, SpaceReport, SubjectReading } from "@mod/erasure-extensions";
import type { ContactStore } from "../store.ts";
import { everyPortOffered } from "./ports.ts";

/**
 * users' eraser, `users`, as its space's `erasedBy` names it: contacts erased through the store's own
 * ports. `erasable` only where the set is offered whole (`everyPortOffered`); one that is not answers
 * empty reports, the field carrying the fact.
 */
export function usersEraser(contacts: ContactStore, reading: SubjectReading): Eraser {
	const { erase, migrate } = contacts;
	if (!everyPortOffered(contacts) || !erase || !migrate) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "users",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => {
		const reports: SpaceReport[] = [await erase.call(contacts, subject, signal)];
		return { reports, logoutGaps: 0 };
	};
	return {
		name: "users",
		erasable: true,
		online,
		// Contacts are keyed by their subject: no walk reaches more.
		window: async (subjects, _walk, signal) => {
			const reports: SpaceReport[] = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => {
			const reports: MigrationReport[] = [await migrate.call(contacts, walk, reading, signal)];
			return reports;
		},
	};
}
