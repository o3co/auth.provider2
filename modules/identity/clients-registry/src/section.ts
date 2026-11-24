import { z } from "zod";

/** The operator section: where the signed version is, whose key signs it, and the least version taken. */
export const section = z.strictObject({
	file: z
		.string()
		.min(1)
		.describe("The path of the file holding the version the publisher signed, read once at boot."),
	"publisher-key": z
		.record(z.string(), z.unknown())
		.describe(
			"The publisher's public key as a JWK, with its kid and its alg (EdDSA over Ed25519, or ES256 over P-256).",
		),
	"min-version": z
		.number()
		.int()
		.positive()
		.describe("The least version number taken: a version below it refuses boot."),
});

export type Settings = z.output<typeof section>;
