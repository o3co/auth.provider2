import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	interval: setting
		.duration("ms")
		.pipe(z.number().int().min(1_000).max(3_600_000))
		.prefault("60s")
		.describe("How often the sample is written, from `1s` to `1h`."),
});
