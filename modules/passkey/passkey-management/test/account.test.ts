import { expect, it } from "vitest";
import { accountOf, masked, nameOf } from "../src/account.ts";

it("shows the address verified last, masked, as `masked` shows an identifier", () => {
	const contacts = [
		{ kind: "email", value: "alice@example.com" },
		{ kind: "email", value: "old@example.org" },
	] as const;
	expect(accountOf(contacts)).toEqual({ account: masked("alice@example.com") });
	expect(accountOf(contacts)).toEqual({ account: "a***@example.com" });
});

it("shows no account where no address is verified, and names one by the deployment and a short mark of its subject", () => {
	expect(accountOf([])).toEqual({});
	expect(nameOf("Example", "s1")).toMatch(/^Example [0-9a-f]{6}$/);
	// The same subject alike each time, another apart: not one name for every account.
	expect(nameOf("Example", "s1")).toBe(nameOf("Example", "s1"));
	expect(nameOf("Example", "s1")).not.toBe(nameOf("Example", "s2"));
});
