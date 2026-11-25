import { firstKeyMail } from "@mod/passkey-management";
import { expect, it } from "vitest";
import { firstKeyWording } from "../src/module.ts";

it("words a first key's mail from its account, link and minutes alone", () => {
	const values = {
		[firstKeyMail.values.account]: "a***@example.com",
		[firstKeyMail.values.link]: "https://login.example/first-key#token",
		[firstKeyMail.values.minutes]: "15",
	};
	const rendered = firstKeyWording.render(values);
	expect(firstKeyWording.purpose).toBe("first-key");
	expect(rendered.subject).toBe("Set up your passkey");
	for (const value of Object.values(values)) expect(rendered.text).toContain(value);
	expect(() => firstKeyWording.render({})).toThrow(TypeError);
});
