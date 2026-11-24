import { type ClaimsSelections, claimsSelections, type Selection } from "@mod/claims-selection";
import type { Client } from "@mod/clients";
import type { BuildContext } from "@mod/kernel";
import { claimsAsked } from "@mod/oidc";

/**
 * A `claims` parameter as T holds it, read at ②, before T is made: why it is refused, or none. It
 * asks an ID token's or userinfo's claims, so it is taken for an OpenID request alone.
 */
export function claimsRefusal(claims: unknown, openid: boolean): string | undefined {
	if (claims === undefined) return undefined;
	if (!openid) return "claims are asked of an ID token or userinfo, for an openid request alone";
	return claimsAsked(claims) === "malformed" ? "the claims parameter is malformed" : undefined;
}

/** What an OpenID request's claims select: none asked, the selection, or a `sub` asked that is not the subject. */
export type Picked =
	| { readonly kind: "none" }
	| { readonly kind: "selected"; readonly selection: Selection }
	| { readonly kind: "otherSubject" }
	| { readonly kind: "acrUnmet" };

/** How the finish selects an OpenID request's claims and pins them to its code. */
export interface ClaimsPinning {
	/**
	 * The names the client is allowed and the person agreed to in this approval (O19): its scope's
	 * words, and the names its `claims` asked, as T holds them.
	 */
	select(
		client: Client,
		subject: string,
		scope: readonly string[],
		claims: unknown,
		/** The acr the login meets, which an essential acr asked is held to. */
		acr: string | undefined,
	): Promise<Picked>;
	/** Kept for the code by its digest, for its lifetime and a minute more (`claims-selection`). */
	keep: ClaimsSelections["keepForCode"];
}

export function claimsPinning(
	selections: Pick<ClaimsSelections, "select" | "keepForCode">,
): ClaimsPinning {
	return {
		select: async (client, subject, scope, claims, acr) => {
			if (claims === undefined) return { kind: "none" };
			const asked = claimsAsked(claims);
			// Read at ② already: one that reads otherwise now is no request the start let through.
			if (asked === "malformed")
				throw new TypeError("authorize: claims read malformed at the finish");
			// Core §5.5.1: a `sub` asked is the one subject the login may answer for.
			if (asked.subs.some((subs) => !subs.includes(subject))) return { kind: "otherSubject" };
			// §5.5.1.1: an essential acr is met by the login's own, one of its values where it names any.
			const met = (values: readonly string[]) =>
				acr !== undefined && (values.length === 0 || values.includes(acr));
			if (asked.acr.some((one) => one.essential && !met(one.values))) return { kind: "acrUnmet" };
			const { idToken, userinfo } = asked.selection;
			const names = [...new Set([...idToken.names, ...userinfo.names].map(({ name }) => name))];
			const agreed = { scopes: scope, names };
			return {
				kind: "selected",
				selection: await selections.select(client, subject, asked.selection, agreed),
			};
		},
		keep: (redemption, selection, lifetimeMs, subject) =>
			selections.keepForCode(redemption, selection, lifetimeMs, subject),
	};
}

/** What the claims' pinning takes from the composition. */
export const claimsTakes = [claimsSelections] as const;

export const claimsPinningIn = async (c: Pick<BuildContext<unknown>, "get">) =>
	claimsPinning(await c.get(claimsSelections));
