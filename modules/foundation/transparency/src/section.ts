import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	lease: setting
		.duration("ms")
		.pipe(z.number().int().min(1))
		.prefault("5s")
		.describe(
			"How long an intent's owner holds it, judged on the store clock; longer than a Core request's deadline.",
		),
});
