import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"per-source": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(3)
		.describe(
			"Subjects sign-ups make per source in each window: each is a new subject in the ledger.",
		),
	total: z
		.number()
		.int()
		.min(1)
		.max(10_000_000)
		.prefault(1000)
		.describe("Subjects sign-ups make from every source together in each window."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe("The window sign-ups are counted over, from 1s to 1d."),
});

export type Settings = z.output<typeof section>;
