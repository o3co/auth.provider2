import type { RequestClaims } from "@mod/authorize";
import type { ClaimsSelections } from "@mod/claims-selection";
import { claimsAsked, type HintReader } from "@mod/oidc";

/**
 * A `claims` parameter as T holds it, read at ②, before T is made: why it is refused, or none. It
 * asks an ID token's or userinfo's claims, so it is taken for an OpenID request alone.
 */
export function claimsRefusal(claims: unknown, openid: boolean): string | undefined {
	if (claims === undefined) return undefined;
	if (!openid) return "claims are asked of an ID token or userinfo, for an openid request alone";
	return claimsAsked(claims) === "malformed" ? "the claims parameter is malformed" : undefined;
}

/**
 * An OpenID request's claims as `authorize` reads them: refused at ②, and at the finish the names
 * the client is allowed and the person agreed to in this approval (O19), its scope's words and the
 * names its `claims` asked as T holds them, kept for the code by `claims-selection`.
 */
export function claimsReading(
	selections: Pick<ClaimsSelections, "select" | "keepForCode">,
	/** oidc's reader of an `id_token_hint`, where oidc is composed; without, no hint is read. */
	hints?: HintReader,
): RequestClaims {
	return {
		refusal: claimsRefusal,
		...(hints ? { hint: (hint: string, clientId: string) => hints.subjectOf(hint, clientId) } : {}),
		select: async (client, subject, scope, claims, acr) => {
			if (claims === undefined) return { kind: "none" };
			const asked = claimsAsked(claims);
			// Read at ② already: one that reads otherwise now is no request the start let through.
			if (asked === "malformed")
				throw new TypeError("authorize-claims: claims read malformed at the finish");
			// Core §5.5.1: a `sub` asked is the one subject the login may answer for.
			if (asked.subs.some((subs) => !subs.includes(subject))) return { kind: "otherSubject" };
			// §5.5.1.1: an essential acr is met by the login's own, one of its values where it names any.
			const met = (values: readonly string[]) =>
				acr !== undefined && (values.length === 0 || values.includes(acr));
			if (asked.acr.some((one) => one.essential && !met(one.values))) return { kind: "acrUnmet" };
			const { idToken, userinfo } = asked.selection;
			const names = [...new Set([...idToken.names, ...userinfo.names].map(({ name }) => name))];
			const selection = await selections.select(client, subject, asked.selection, {
				scopes: scope,
				names,
			});
			return {
				kind: "selected",
				keep: (digest, lifetimeMs, keptFor) =>
					selections.keepForCode(digest, selection, lifetimeMs, keptFor),
			};
		},
	};
}
