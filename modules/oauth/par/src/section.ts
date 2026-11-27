import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"pushed-only": z
		.boolean()
		.prefault(true)
		.describe(
			"Whether a login's request is taken pushed alone (FAPI 2.0), never by value: `false` takes a JAR by value too, outside a FAPI configuration.",
		),
	"jar-max-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(10).max(600))
		.prefault("90s")
		.describe("The longest a pushed JAR may still live, from `10s` to `10m` in whole seconds."),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe("Pushed requests allowed per source in each window."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The window pushed requests are counted over, from 1s to 1d."),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(300))
		.prefault("30s")
		.describe(
			"How long a pushed request is kept past its JAR's expiry, from `1s` to `5m` in whole seconds.",
		),
});

export type Settings = z.output<typeof section>;
