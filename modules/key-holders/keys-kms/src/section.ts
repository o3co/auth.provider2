import { z } from "zod";

/** The operator section: the region, and the KMS key each kid names. */
export const section = z
	.strictObject({
		region: z.string().min(1).describe("The AWS region the keys are in."),
		keys: z
			.array(
				z.strictObject({
					kid: z.string().min(1).describe("The kid `keys` names the key by."),
					"key-id": z
						.string()
						.min(1)
						.describe("The KMS key: its ARN (preferred), its id, or an alias's name or ARN."),
				}),
			)
			.describe("The keys held, each kid once."),
	})
	.superRefine((s, ctx) => {
		const seen = new Set<string>();
		for (const [i, { kid }] of s.keys.entries()) {
			if (seen.has(kid)) {
				ctx.addIssue({ code: "custom", message: "duplicate kid", path: ["keys", i, "kid"] });
			}
			seen.add(kid);
		}
	});

export type Section = z.output<typeof section>;
