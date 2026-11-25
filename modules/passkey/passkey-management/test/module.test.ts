import { contract, defineModule } from "@mod/kernel";
import { type MailPurpose, mailPurposes } from "@mod/mail";
import { expect, it } from "vitest";
import { firstKeyMail } from "../src/contract.ts";
import passkeyManagement from "../src/module.ts";
import { composed } from "./fixtures/composed.ts";

const seen = contract<readonly MailPurpose[]>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [mailPurposes] },
	(m) => [m.provide(seen).by((c) => c.collect(mailPurposes))],
);

it("declares its mail's purpose to mail, whose wording a template gives", async () => {
	const { app } = await composed({ modules: [collecting] });
	expect(app.get(seen)).toEqual([{ purpose: firstKeyMail.purpose }]);
});

it("takes the mail's link alone, and a token of 15 minutes, 3 tries and nonces of 2 by default", () => {
	expect(passkeyManagement.section?.parse({ "mail-link": "https://login.example/k" })).toEqual({
		"mail-link": "https://login.example/k",
		"token-lifetime": 900,
		"code-tries": 3,
		"nonce-lifetime": 120,
		requests: 30,
		window: 60,
		"inbox-only-when-absent": false,
	});
});

it("refuses a link not https, and lifetimes and tries outside their bounds", () => {
	const parsed = (settings: Record<string, unknown>) =>
		passkeyManagement.section?.safeParse({ "mail-link": "https://login.example/k", ...settings })
			.success;
	expect(parsed({ "mail-link": "http://login.example/k" })).toBe(false);
	expect(passkeyManagement.section?.safeParse({}).success).toBe(false);
	for (const settings of [
		{ "token-lifetime": "30s" },
		{ "token-lifetime": "2h" },
		{ "code-tries": 0 },
		{ "code-tries": 11 },
		{ "nonce-lifetime": "10s" },
		{ "nonce-lifetime": "11m" },
	]) {
		expect(parsed(settings), JSON.stringify(settings)).toBe(false);
	}
});
