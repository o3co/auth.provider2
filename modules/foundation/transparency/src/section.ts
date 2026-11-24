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
	tending: setting
		.duration("ms")
		.pipe(z.number().int().min(1000))
		.prefault("30s")
		.describe(
			"How often each replica tends the client flows, closing an op whose owner fell: at least a second.",
		),
});
