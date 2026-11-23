import { z } from "zod";

/** Written as PEM, so a placeholder or a key in another form is refused here, before it is read. */
const pem = z.string().regex(/^\s*-----BEGIN [A-Z0-9 ]+-----/, "a PEM");

const entry = z
	.strictObject({
		kid: z.string().min(1).describe("The kid `keys` names the key by."),
		pem: pem
			.optional()
			.describe(
				"The key as PEM: a private key (PKCS8 or the key's own form) signs and agrees; a public key or a certificate only verifies.",
			),
		file: z
			.string()
			.min(1)
			.optional()
			.describe("The path of a file holding the key as PEM, read at boot, in place of `pem`."),
	})
	.refine((e) => (e.pem === undefined) !== (e.file === undefined), {
		message: "one of pem and file",
	});

/** The operator section: the keys it holds, each by its kid, written in the configuration or in a file. */
export const section = z
	.strictObject({
		keys: z.array(entry).describe("The keys held, each kid once."),
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
