import type { SubjectReading } from "@mod/erasure-extensions";
import { expect, it } from "vitest";
import { contactSubjectOf } from "../../contacts/contacts.ts";
import type { ContactStore } from "../../store.ts";
import { memoryUsersStores } from "../../testing.ts";
import { usersEraser } from "../eraser.ts";

/** The reading as the package composes it. */
const reading: SubjectReading = async (key, value) => contactSubjectOf(key, value);
const walk = { sweep: async () => ({ keys: [], server: "s" }) };
const signal = new AbortController().signal;

/** A contact store offering its ports, noting what each erase and migrate was given. */
function ported() {
	const memory = memoryUsersStores();
	const seen: { erased: string[]; readings: SubjectReading[] } = { erased: [], readings: [] };
	const contacts = {
		...(memory.contacts.store as unknown as ContactStore),
		erase: async (subject: string) => {
			seen.erased.push(subject);
			return { kind: "erased", space: "users-store.contacts", removed: 0 } as never;
		},
		migrate: async (_w: unknown, given: SubjectReading) => {
			seen.readings.push(given);
			return { kind: "migrated", space: "users-store.contacts", indexed: 0, removed: 0 } as never;
		},
	} as ContactStore;
	return { memory, contacts, seen };
}

it("is erasable only where the contact store offers its erase and migrate", async () => {
	const memory = memoryUsersStores();
	const bare = usersEraser(memory.contacts.store, reading);
	expect([bare.name, bare.erasable]).toEqual(["users", false]);
	expect(await bare.online("s-a", signal)).toEqual({ reports: [], logoutGaps: 0 });
	expect(usersEraser(ported().contacts, reading).erasable).toBe(true);
});

it("erases a subject's contacts through the store's port, for each subject of a window", async () => {
	const { contacts, seen } = ported();
	const eraser = usersEraser(contacts, reading);
	expect((await eraser.online("s-a", signal)).reports).toHaveLength(1);
	await eraser.window(["s-b", "s-c"], walk, signal);
	expect(seen.erased).toEqual(["s-a", "s-b", "s-c"]);
});

it("reads a contact list as its key's, and any other shape as proving nothing", async () => {
	const { contacts, seen } = ported();
	await usersEraser(contacts, reading).migrate(walk, signal);
	const [inContacts] = seen.readings;
	expect(await inContacts?.("s-a", [])).toEqual({ kind: "subject", subject: "s-a" });
	expect((await inContacts?.("s-a", { list: [] }))?.kind).toBe("unreadable");
});
