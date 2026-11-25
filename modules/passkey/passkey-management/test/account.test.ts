import { expect, it } from "vitest";
import { accountOf, masked, nameOf } from "../src/account.ts";

it("shows the address verified last, masked, as a first key's mail shows its identifier", () => {
	const contacts = [
		{ kind: "email", value: "alice@example.com" },
		{ kind: "email", value: "old@example.org" },
	] as const;
	expect(accountOf(contacts, "Example", "s1")).toEqual({ account: masked("alice@example.com") });
	expect(accountOf(contacts, "Example", "s1")).toEqual({ account: "a***@example.com" });
});

it("names an account no address names by the deployment and a short mark of its subject", () => {
	// Named, not masked: F1's name, in the creation's `user_name`, never its `account`.
	expect(accountOf([], "Example", "s1")).toEqual({ userName: nameOf("Example", "s1") });
	expect(nameOf("Example", "s1")).toMatch(/^Example [0-9a-f]{6}$/);
	// The same subject alike each time, another apart: not one name for every account.
	expect(nameOf("Example", "s1")).toBe(nameOf("Example", "s1"));
	expect(nameOf("Example", "s1")).not.toBe(nameOf("Example", "s2"));
});
