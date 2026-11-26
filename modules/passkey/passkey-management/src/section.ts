import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(30)
		.describe(
			"Requests allowed per source in each window, to each of `/continue`, `/key/finish`, `/approval/start` and `/approval/finish`.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The window they are counted over, from 1s to 1d."),
	"account-name": z
		.string()
		.regex(/^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,50}$/u)
		.optional()
		.describe(
			"The deployment's name a passkey shows for an account no address names, beside a short mark of its subject; by default the relying party ID, its first 50 characters, which may end inside a label: set it where the ID is longer.",
		),
});

export type Settings = z.output<typeof section>;
