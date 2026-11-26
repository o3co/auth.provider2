import type { Section } from "@mod/clients";
import { checkField } from "@mod/front-core-codec";
import { requests } from "@mod/front-core-wire";
import { z } from "zod";

/** A client's own token request crosses a Front as front-core-wire's clientCredentials: what it carries. */
const carried = Object.fromEntries(
	requests.clientCredentials.fields.map((field) => [field.name, field]),
);
const encoder = new TextEncoder();
/** Whether a value fits a field of the client's own token request, as the codec checks it. */
const fits = (name: "resource" | "scope", value: string) => {
	const field = carried[name];
	return field !== undefined && checkField(field, encoder.encode(value)) === undefined;
};

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

/**
 * A scope of the client's own ceiling: never `openid` either, which asks for a person's identity a
 * client's own token, whose subject is the client, never carries.
 */
const selfScope = scope.refine(
	(name) => name !== "openid",
	"openid asks for a person's identity, which a client's own token never carries, so remove it",
);

export const allowances: Section<Allowances> = {
	name: "client-allowance",
	// A registered client is never of a signed version, so its own ceiling would be read by no one.
	checkAtBoot: (value) =>
		value.self.length > 0
			? "self is read only for a client of a version its publisher signed: write it in the publisher's registry"
			: undefined,
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
			.array(z.strictObject({ audience: z.string().min(1), scopes: z.array(selfScope) }))
			.prefault([])
			.superRefine((entries, context) => {
				for (const [i, entry] of entries.entries()) {
					if (entries.findIndex((e) => e.audience === entry.audience) < i)
						context.addIssue({
							code: "custom",
							message: "an audience is written in one entry alone",
							path: [i, "audience"],
						});
					// Asked through a Front, the audience goes as the request's one resource and the scopes as
					// its scope: an entry the wire cannot carry could never be asked there, so it is refused.
					if (!fits("resource", entry.audience))
						context.addIssue({
							code: "custom",
							message:
								"an audience the Front's wire cannot carry as a resource (its length or characters)",
							path: [i, "audience"],
						});
					// The longest scope a client asks for all of them: each scope once.
					if (!fits("scope", [...new Set(entry.scopes)].join(" ")))
						context.addIssue({
							code: "custom",
							message: "scopes the Front's wire cannot carry together as a scope (their length)",
							path: [i, "scopes"],
						});
				}
			})
			.describe(
				"The client's own ceiling, for a token it takes for itself: each entry an audience and the scopes it may be issued there, never `offline_access` or `openid`. Read only for a client of a version its publisher signed; none allows nothing. The person's delegation (`scopes`, `audiences`) is never read for it.",
			),
	}),
};
