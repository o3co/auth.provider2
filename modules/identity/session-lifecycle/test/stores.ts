import { defineModule, Unavailable } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type ClosingList,
	closingList,
	type SessionStore,
	type StoredSession,
	type SubjectSessions,
	sessionStore,
	sessionsPerSubject,
	subjectSessions,
} from "../src/store.ts";

/**
 * session-lifecycle's store interfaces on the records stand-in, with lifetimes on the composition's
 * clock, the listing at the cap session-lifecycle gives; each goes through a switch that can make its
 * calls unavailable.
 */
export function memoryStores() {
	let clock = () => 0;
	const size = { shards: 4, perShard: 50 };
	const kept = memoryRecords<StoredSession>(() => clock(), size);
	const down = {
		sessions: unavailableSwitch<SessionStore>("session store"),
		closing: unavailableSwitch<ClosingList>("closing list"),
		listed: unavailableSwitch<SubjectSessions>("subject sessions"),
	};
	/** Subjects erased: a session saved, or a listing added, for one is answered `erased`, as a Store that erases does. */
	const erased = { sessions: new Set<string>(), listed: new Set<string>() };
	/** The writes that take effect once more and then answer Unavailable, as a place whose answer was lost. */
	const lost = new Set<"sessions.save" | "listed.add">();
	const answered = async <T>(write: "sessions.save" | "listed.add", done: Promise<T>) => {
		const value = await done;
		if (lost.delete(write)) throw new Unavailable(write);
		return value;
	};
	const module = defineModule(
		{ name: "session-stores", replicaSafe: false, takes: [sessionsPerSubject] },
		(m) => [
			m.provide(sessionStore).by((c) => {
				clock = c.clock.now;
				const { create: save, read, change: update } = kept.records;
				return down.sessions.wrap({
					save: async (handle, record, lifetimeMs, subject) =>
						erased.sessions.has(subject)
							? "erased"
							: answered("sessions.save", save(handle, record, lifetimeMs)),
					read,
					update,
				});
			}),
			m.provide(closingList).by(() => down.closing.wrap(kept.deferred)),
			m.provide(subjectSessions).by(async (c) => {
				const sets = kept.keyedSets(await c.get(sessionsPerSubject));
				return down.listed.wrap({
					...sets,
					add: async (subject, handle, lifetimeMs) =>
						erased.listed.has(subject)
							? "erased"
							: answered("listed.add", sets.add(subject, handle, lifetimeMs)),
				});
			}),
		],
	);
	/** The members listed under a subject, each with its time left, read past the switch. */
	const members = (subject: string) => kept.keyedSets(1).members(subject);
	return { module, kept, down, lost, erased, members };
}
