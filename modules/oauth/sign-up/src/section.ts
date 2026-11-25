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
			"Sign-up runs per source in each window: a first, cheap count while the Front is honest, never relied on, as the source is its word.",
		),
	"per-client": z
		.number()
		.int()
		.min(1)
		.max(1_000_000)
		.prefault(100)
		.describe(
			"Sign-up runs per client (the authorization's, from its signed JAR) in each window: with the total, what the counts rest on. It keeps one client from the total only while below `total`.",
		),
	total: z
		.number()
		.int()
		.min(1)
		.max(10_000_000)
		.prefault(1000)
		.describe(
			"Sign-up runs of every source and client together in each window: each run may make a new subject in the ledger.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe("The window sign-ups are counted over, from 1s to 1d."),
});

export type Settings = z.output<typeof section>;
