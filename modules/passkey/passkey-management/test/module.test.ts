import { expect, it } from "vitest";
import passkeyManagement from "../src/module.ts";

it("takes nothing it needs set: 30 requests a minute per source, and the account's name by default the RP ID", () => {
	expect(passkeyManagement.section?.parse({})).toEqual({ requests: 30, window: 60 });
	expect(passkeyManagement.section?.parse({ "account-name": "Example" })).toMatchObject({
		"account-name": "Example",
	});
});

it("refuses a first key's setting, a name outside its form, and counts outside their bounds", () => {
	const parsed = (settings: Record<string, unknown>) =>
		passkeyManagement.section?.safeParse(settings).success;
	for (const settings of [
		{ "mail-link": "https://login.example/k" },
		{ "account-name": "" },
		{ "account-name": "a".repeat(51) },
		{ "account-name": "a\u0000b" },
		{ requests: 0 },
		{ window: "0s" },
	]) {
		expect(parsed(settings), JSON.stringify(settings)).toBe(false);
	}
});
