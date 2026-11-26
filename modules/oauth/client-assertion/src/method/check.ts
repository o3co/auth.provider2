import type { Verified } from "@mod/external-jwt";
import { z } from "zod";
import { said } from "../check.ts";

export type Checked =
	| {
			readonly kind: "valid";
			readonly jti: string;
			readonly expiresAt: number;
			/** Whether `aud` is the issuer's URL as one string, not the token endpoint's and not a list. */
			readonly forIssuer: boolean;
	  }
	| { readonly kind: "invalid"; readonly reason: string };

const claimsShape = z.object({
	jti: z
		.string()
		.min(1)
		.max(256)
		.refine((s) => s.isWellFormed()),
	exp: z.number(),
});

/** What this module reads of a verified assertion: its `jti`, when it ends, and whether it is for `issuer` alone. */
export function checked(
	verified: Exclude<Verified, { kind: "unavailable" }>,
	issuer: string,
): Checked {
	if (verified.kind === "invalid") return { kind: "invalid", reason: said[verified.reason] };
	const claims = claimsShape.safeParse(verified.claims);
	if (!claims.success) return { kind: "invalid", reason: "missing or malformed claims" };
	return {
		kind: "valid",
		jti: claims.data.jti,
		expiresAt: claims.data.exp * 1000,
		forIssuer: verified.claims.aud === issuer,
	};
}
