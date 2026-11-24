import { setting } from "@mod/kernel";
import { attributeCaps } from "@mod/login-attributes";
import { z } from "zod";

export const section = z.strictObject({
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often each host goes on with pending closes, from 1s to 1h, such as 1m; a close whose participants keep failing is retried after half its age, at least this, at most an hour.",
		),
	"sessions-per-subject": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe(
			"How many sessions, each an authorization still live, a subject's listing holds, from 1 to 10000; past it, the one ending first is closed. A login rewrites its subject's listing whole.",
		),
	attributes: attributeCaps.describe(
		"The caps a login's attributes are kept within, as login-attributes reads them; lowering one drops, when an open session's attributes are read back, a value past it.",
	),
});
