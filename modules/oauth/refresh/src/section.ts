import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	lifetime: setting
		.duration("s")
		.pipe(z.number().int().min(300).max(31_536_000))
		.prefault("1d")
		.describe(
			"How long a login's delegation lasts from its statement's issue, from 5m to 1y: its refresh family's and its session's.",
		),
});
