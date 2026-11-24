import type { Section } from "@mod/clients";
import { z } from "zod";

/** One entry of the client's own ceiling: an audience and the scopes it may be issued for itself there. */
export interface SelfEntry {
	readonly audience: string;
	readonly scopes: readonly string[];
}

export interface Allowances {
	readonly grants: readonly string[];
	readonly scopes: readonly string[];
	readonly "default-scopes"?: readonly string[] | undefined;
	readonly audiences: readonly string[];
	/** The client's own ceiling, apart from what a person delegates: audience and scope pairs. */
	readonly self: readonly SelfEntry[];
}

/** A scope the client may be allowed: never `offline_access`, which allows nothing here, offline access not being offered. */
const scope = z
	.string()
	.refine(
		(name) => name !== "offline_access",
		"offline_access allows nothing: offline access is not offered, so remove it",
	);

export const allowances: Section<Allowances> = {
	name: "client-allowance",
	schema: z.strictObject({
		grants: z
			.array(z.string())
			.prefault([])
			.describe("The grant types the client may use; none allows no grant."),
		scopes: z
			.array(scope)
			.prefault([])
			.describe("The scopes the client may ask for; none allows no scope."),
		"default-scopes": z
			.array(scope)
			.optional()
			.describe(
				"The scopes given when the client asks none; left out, a request without a scope is refused while scopes are allowed, and an empty list gives no scope.",
			),
		audiences: z
			.array(z.string())
			.prefault([])
			.describe(
				"The audiences the client's tokens may name, the first given when none is asked; none means the issuer.",
			),
		self: z
			.array(z.strictObject({ audience: z.string().min(1), scopes: z.array(scope) }))
			.prefault([])
			.superRefine((entries, context) => {
				for (const [i, entry] of entries.entries()) {
					if (entries.findIndex((e) => e.audience === entry.audience) < i)
						context.addIssue({
							code: "custom",
							message: "an audience is written in one entry alone",
							path: [i, "audience"],
						});
				}
			})
			.describe(
				"The client's own ceiling, for a token it takes for itself: each entry an audience and the scopes it may be issued there. Read only for a client of a version its publisher signed; none allows nothing. The person's delegation (`scopes`, `audiences`) is never read for it.",
			),
	}),
};
