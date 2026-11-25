import type { Target } from "@mod/claims-selection";
import { contract } from "@mod/kernel";
import type { Claim } from "./claims/claims.ts";

export {
	type Claim,
	type ClaimsAsked,
	claimsAsked,
	scopeOfClaim,
	tableClaims,
	tableScopes,
} from "./claims/claims.ts";
export { idTokenTyp } from "./id-token/id-token.ts";

/** The claims `oidc` releases for a subject outside an ID token: what userinfo answers. */
export interface ReleasedClaims {
	/**
	 * The table's claims released from the subject's attributes, read through `subject-attributes`
	 * with the session's handle, for the scope words and what a request asked beyond them, its
	 * constraints holding back; `email_verified` only where `users` vouches. None where neither
	 * source can say; never `sub`. Throws Unavailable where the attributes cannot be read.
	 */
	of(
		subject: string,
		scope: readonly string[],
		session: string,
		asked?: Target,
	): Promise<Readonly<Record<string, Claim>>>;
}

export const releasedClaims = contract<ReleasedClaims>("oidc.released-claims");
