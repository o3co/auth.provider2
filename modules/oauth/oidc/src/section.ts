import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"id-token-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("1h")
		.describe("How long an ID token lives, from 1m to 1d."),
});
