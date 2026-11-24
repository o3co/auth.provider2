import { readSecretWork, type SecretWork } from "@mod/secret-hash";
import { z } from "zod";

export const section = z.strictObject({
	"password-work": z
		.string()
		.transform((text, ctx): SecretWork => {
			const work = readSecretWork(text);
			if (!work) {
				ctx.addIssue({
					code: "custom",
					message: "a work secret-hash reads, such as scrypt:15,8,1,32,16",
				});
				return z.NEVER;
			}
			return work;
		})
		.describe(
			"The work of every password's hash it holds, as secret-hash names it (`bcrypt:12`, `scrypt:15,8,1,32,16`): an identifier held with no password is checked with this work too.",
		),
});
