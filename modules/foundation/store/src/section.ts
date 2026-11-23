import { z } from "zod";

export const section = z.strictObject({
	"accept-volatile": z
		.boolean()
		.prefault(false)
		.describe("Whether spaces that need durable or replicated storage may boot on memory."),
	"accept-unauthenticated": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether spaces that need authenticated storage may boot on a store that does not tell a write made outside the provider apart.",
		),
});
