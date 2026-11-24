import { assemble, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { expect, it, vi } from "vitest";
import { users } from "../../contract.ts";
import usersModule from "../../module.ts";
import type { SubjectRecordStore } from "../../store.ts";
import { memoryUsersStores, testUser, usersConfig } from "../../testing.ts";
import { keptFor } from "../kept-for.ts";

it("saves a verified contact with the subject it is kept for", async () => {
	const stores = memoryUsersStores();
	const contactSave = vi.spyOn(stores.contacts.store, "save");
	const app = await assemble({
		modules: [usersModule, secretHashModule, stores.module],
		config: { ...kernelConfig(), ...usersConfig([testUser("alice", "pw")]) },
		runtime: quietRuntime(),
	});
	const people = app.get(users);
	await people.verifiedContact("s-alice", { kind: "email", value: "a@example.com" });
	expect(contactSave).toHaveBeenCalledWith("s-alice", expect.anything(), "endless", "s-alice");
});

/** A record store whose saves answer as scripted, finding nothing to change while it does. */
const scripted = (answers: ("created" | "exists")[]): SubjectRecordStore<number> => ({
	save: async () => answers.shift() ?? "created",
	read: async () => undefined,
	update: async () => undefined,
});

it("saves again a record a create met and a read then found gone, never answering it as another's", async () => {
	const kept = await keptFor(
		scripted(["exists", "exists", "created"]),
		"k",
		1,
		() => undefined,
		"s",
	);
	expect(kept).toEqual({ before: undefined, after: 1 });
});

it("is unavailable after a bounded number of such attempts", async () => {
	const always = scripted(Array.from({ length: 20 }, () => "exists" as const));
	await expect(keptFor(always, "k", 1, () => undefined, "s")).rejects.toSatisfy(isUnavailable);
});
