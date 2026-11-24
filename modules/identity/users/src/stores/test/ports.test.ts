import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import type { ContactStore } from "../../store.ts";
import { keptFor } from "../kept-for.ts";
import { portsRefused } from "../ports.ts";

const nothing = async () => undefined;
const base = { save: async () => "created" as const, read: nothing, update: nothing };
const erase = async () => ({}) as never;
const migrate = async () => ({}) as never;

it("takes a contact store's erase and migrate together, or neither", () => {
	const contacts = base as ContactStore;
	expect(portsRefused(contacts)).toBeUndefined();
	expect(portsRefused({ ...contacts, erase, migrate })).toBeUndefined();
	expect(portsRefused({ ...contacts, erase })).toBe(
		"the contact store offers one of erase and migrate: it offers both, or neither",
	);
});

it("is unavailable where the store answers that the subject is erased, never another's answer", async () => {
	const erased = { ...base, save: async () => "erased" as const };
	await expect(keptFor(erased, "k", 1, () => undefined, "s-gone")).rejects.toSatisfy(isUnavailable);
});
