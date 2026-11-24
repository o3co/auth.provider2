import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"code-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(10).max(60))
		.prefault("60s")
		.describe("How long a code can be redeemed, from 10s to 60s."),
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often each host retries the revocations a code that came again left, from 1s to 1h.",
		),
});
