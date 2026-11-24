import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"screen-url": z
		.url({ protocol: /^https$/ })
		.describe(
			"The static login screen's URL, where an RP sends the browser with its JAR: published as the authorization endpoint. https only.",
		),
	"jar-max-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(30).max(3600))
		.prefault("10m")
		.describe(
			"The longest a JAR may still live when it starts a login, from `30s` to `1h` in whole seconds.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(30)
		.describe("Starts allowed per source in each window."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The window starts are counted over, from 1s to 1d."),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(300))
		.prefault("30s")
		.describe(
			"How long a JAR's reservation is kept past its expiry, from `1s` to `5m` in whole seconds: more than replicas' clocks may differ, as a JAR is taken only before its expiry.",
		),
});

export type Settings = z.output<typeof section>;
