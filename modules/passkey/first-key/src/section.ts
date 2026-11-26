import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"mail-link": z
		.url({ protocol: /^https$/ })
		.describe(
			"The login screen's page a first key's mail links to, the token in its fragment. https only.",
		),
	"token-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(3600))
		.prefault("15m")
		.describe("How long a first key's mail token lives, from `1m` to `1h` in whole seconds."),
	"code-tries": z
		.number()
		.int()
		.min(1)
		.max(10)
		.prefault(3)
		.describe(
			"Wrong codes, or identifiers naming another subject, a token takes before it is revoked.",
		),
	"nonce-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(30).max(600))
		.prefault("2m")
		.describe(
			"How long a nonce of a first key's stage lives, from `30s` to `10m` in whole seconds.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(30)
		.describe(
			"Requests allowed per source in each window, to each of `/first-key/nonce`, `/first-key/start`, `/first-key/mail` and `/first-key/recover`.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The window they are counted over, from 1s to 1d."),
	"inbox-only-when-absent": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether one answering `absent` to every kind of evidence composed passes on the inbox alone; declared in the evidence's strength where on.",
		),
});

export type Settings = z.output<typeof section>;
