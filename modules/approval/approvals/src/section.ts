import { setting } from "@mod/kernel";
import { windowCeilingMs } from "@mod/rate-limit";
import { z } from "zod";

export const section = z.strictObject({
	"statement-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(30).max(3600))
		.prefault("5m")
		.describe("How long a statement may be used once issued, from `30s` to `1h` in whole seconds."),
	"issue-limit": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(30)
		.describe("How many statements one key a caller counts by may be issued in `issue-window`."),
	"issue-total": z
		.number()
		.int()
		.min(1)
		.max(10_000_000)
		.prefault(100_000)
		.describe("How many statements every replica together may issue in `issue-window`."),
	"issue-window": setting
		.duration("ms")
		.pipe(z.number().int().min(1000).max(windowCeilingMs))
		.prefault("1m")
		.describe("The window `issue-limit` counts in, from `1s` to a day."),
	"max-concurrent": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(64)
		.describe("How many statements this process signs at once; more are refused as busy."),
});

export type Settings = z.output<typeof section>;
