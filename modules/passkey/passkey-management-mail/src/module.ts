import { defineModule } from "@mod/kernel";
import { mailTemplates, plainText } from "@mod/mail";
import { firstKeyMail } from "@mod/passkey-management";

const { link, account, minutes } = firstKeyMail.values;

/** A first key's mail, in English: the account it is for, its link, and how long the link lives. */
export const firstKeyWording = plainText(firstKeyMail.purpose, {
	subject: "Set up your passkey",
	text: [
		`Someone asked to set up a passkey for the account {${account}}.`,
		"",
		"If it was you, open this link on the device the passkey is for, and enter the code the",
		"screen you started on shows:",
		"",
		`{${link}}`,
		"",
		`The link works once, for {${minutes}} minutes. If it was not you, ignore this mail: no`,
		"passkey is set up without the link and the code.",
	].join("\n"),
});

// Holds nothing of its own: a deployment changes the wording by replacing this module.
export default defineModule(
	{ name: "passkey-management-mail", replicaSafe: true, takes: [] },
	(m) => [m.contribute(mailTemplates).by(() => firstKeyWording)],
);
