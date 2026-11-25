import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"user-verification": z
		.enum(["required", "preferred", "discouraged"])
		.prefault("required")
		.describe(
			"Whether an assertion must show the authenticator verified its user, as WebAuthn says it; anything but required breaks the promise that a new login needs the user's passkey.",
		),
	"pending-lifetime": setting
		.duration("ms")
		.pipe(z.number().int().min(1000).max(86_400_000))
		.prefault("10m")
		.describe("How long a reserved key may wait for its possession to be shown and committed."),
	"max-credentials": z
		.number()
		.int()
		.min(1)
		.max(16)
		.prefault(10)
		.describe(
			"The most passkeys a subject may hold, from 1 to 16: the most a list of keys answers in its one padded length.",
		),
});

export type Settings = z.output<typeof section>;
