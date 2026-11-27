import type { Client } from "@mod/clients";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { matches, redirects } from "@mod/redirect-uris";
import { itemsFromJar, jarClaims } from "@mod/sdk-core-wire";
import {
	type CodeNeeds,
	codeNeedsIn,
	codeNeedsTakes,
	targetsIn,
	type Unmet,
} from "../code-needs/code-needs.ts";
import {
	type AuthorizationRequests,
	type CheckedRequest,
	type RequestClaims,
	requestClaims,
} from "../contract.ts";
import { type Refusal, sha256, type Verified } from "../jar/jar.ts";

/** What a request is checked with: what a code needs, and why an OpenID request's `claims` is refused. */
export interface RequestParts {
	/** What a code needs, checked before T (internal module `code-needs`). */
	readonly needs: CodeNeeds;
	/** Why an OpenID request's `claims` is refused before T, and a hint's reader: the `requestClaims` contributed, else `claimsUnread`. */
	readonly claims: Pick<RequestClaims, "refusal" | "hint">;
}

/** Where no module reads a request's `claims`, any is refused before T. */
export const claimsUnread: RequestParts["claims"] = {
	refusal: (claims) => (claims === undefined ? undefined : "the claims parameter is not supported"),
};

/** A code's need unmet, as a request's check answers it before T. */
const unmetRefusal = (unmet: Unmet): Refusal => {
	switch (unmet.need) {
		case "grant":
			return { error: "unauthorized_client", description: "the client may not use the code grant" };
		case "resource":
			return {
				error: "invalid_target",
				description: unmet.description ?? "resource is not the audience asked",
			};
		case "challenge":
			return { error: "invalid_request", description: "code_challenge is malformed" };
		case "scope":
			return { error: "invalid_scope", description: "the scope is not allowed" };
		case "binding":
			return { error: "invalid_request", description: "dpop_jkt is out of its form" };
		default:
			return unmet satisfies never;
	}
};

const refused = (error: string, description: string) => ({ refused: { error, description } });

/**
 * `sdk-core-wire`'s refusal of T's items, read by its spelling (RFC 9101 §6.3: the request object
 * taken, its parameters are OAuth's): an item missing or of a value not allowed (`missing_item:`,
 * `item:`) is the parameter's fault, `invalid_request`; a known item refused (`refused_item:`:
 * `request`, `request_uri`, `authorization_details`), the `claims` (`item:claims`), and any spelling not
 * known are the request object's own, `invalid_request_object`. The wire's spelling is the description.
 */
export function itemsRefusal(error: string): Refusal {
	const at = error.indexOf(":");
	const [kind, name] = at < 0 ? [error, ""] : [error.slice(0, at), error.slice(at + 1)];
	const parameter =
		(kind === "missing_item" || kind === "item") && name !== "" && name !== "claims";
	return { error: parameter ? "invalid_request" : "invalid_request_object", description: error };
}

/**
 * The longest `state` and `nonce`, each in the UTF-8 bytes of its value: this project's own bound
 * (RFC 6749 sets none), so T keeps room within its route beside a long client, redirect URI, scope and
 * `claims`. It counts the value, not its JSON escape in T: the start's `fits` still holds T to its route.
 */
export const itemMaxBytes = 512;
const longer = (value: string) => Buffer.byteLength(value, "utf8") > itemMaxBytes;

/** The words `prompt` takes, each met by the person's tap at every login (D6); `none` is never met. */
const promptWords = new Set(["login", "consent", "select_account"]);

/** `prompt`, which is no item of T: refused where it asks no interaction, dropped where every tap meets it. */
function withoutPrompt(claims: Readonly<Record<string, unknown>>) {
	const { prompt, ...rest } = claims;
	// A null is a parameter sent without a value, so not sent (RFC 6749 §3.1), as the item rule reads it.
	if (prompt === undefined || prompt === null) return { claims: rest };
	const words = typeof prompt === "string" ? prompt.split(" ") : [];
	if (words.includes("none"))
		return refused("login_required", "every login asks the person's passkey");
	if (words.length === 0 || words.some((w) => !promptWords.has(w)))
		return refused("invalid_request", "prompt names a word not taken");
	return { claims: rest };
}

/** The check of a verified JAR's request, over what a code needs and the `claims` reader. */
export function requestsOver(p: RequestParts): AuthorizationRequests {
	// The check alone, whose items' hint_sub is unverified: offered only inside checked.
	const check = (
		client: Client,
		verified: Verified,
		jar: string,
		requestUri?: string,
	): CheckedRequest => {
		const redirectUri = verified.claims.redirect_uri;
		const registered = client.section(redirects)["redirect-uris"];
		if (typeof redirectUri !== "string" || !registered.some((r) => matches(r, redirectUri)))
			return refused("invalid_request", "the redirect URI is not one the client registered");
		const prompted = withoutPrompt(verified.claims);
		if ("refused" in prompted) return prompted;
		// Under PAR, T names the request_uri the start named, as it came, its source having resolved it.
		const made = itemsFromJar(prompted.claims, sha256(jar), requestUri);
		if ("error" in made) return { refused: itemsRefusal(made.error) };
		for (const name of ["state", "nonce"] as const)
			if (longer(made.items[name]))
				return refused("invalid_request", `${name} is longer than ${itemMaxBytes} bytes`);
		// Where no ID token is made, an OpenID request is refused before T, never once the person tapped.
		if (p.needs.openidUnmet(made.items)) return refused("invalid_scope", "no ID token is issued");
		// Its claims, read before T is made: one asked malformed, or without openid, is refused.
		const claimsRefused = p.claims.refusal(made.items.claims, p.needs.asksOpenid(made.items.scope));
		if (claimsRefused) return refused("invalid_request_object", claimsRefused);
		// What a code needs, before T, so the finish fails on none of it once the person tapped.
		const unmet = p.needs.atStart(client, made.items);
		if (unmet) return { refused: unmetRefusal(unmet) };
		return { items: made.items };
	};
	return {
		checked: async (client, verified, jar, requestUri) => {
			const made = check(client, verified, jar, requestUri);
			const hint = verified.claims[jarClaims.hint];
			if ("refused" in made || typeof hint !== "string") return made;
			const read = p.claims.hint
				? await p.claims.hint(hint, client.id)
				: { refused: "an id_token_hint is not read here" };
			if ("refused" in read) return refused("invalid_request", read.refused);
			// Its verified subject is the one T holds, read unverified: a payload that reads otherwise is none.
			return read.subject === made.items.hint_sub
				? made
				: refused(
						"invalid_request",
						"the id_token_hint reads as another subject than it is verified for",
					);
		},
	};
}

/** What the check takes from the composition. */
export const requestsTakes = [issuer, requestClaims, ...codeNeedsTakes] as const;

/**
 * The check over the composition: the `claims` reader and the rule for the audience asked, at most
 * one of each, else boot is refused.
 */
export async function requestsIn(
	c: Pick<BuildContext<unknown>, "get" | "collect" | "refuse">,
): Promise<AuthorizationRequests> {
	const readers = await c.collect(requestClaims);
	if (readers.length > 1)
		return c.refuse("authorize", "more than one module reads a request's claims");
	// At most one rule reads `resource`, as at the token endpoint, which may not be composed.
	if ((await targetsIn(c)).length > 1)
		return c.refuse("authorize", "more than one rule reads the audience asked (resource)");
	return requestsOver({
		needs: await codeNeedsIn(c, (await c.get(issuer)).url),
		claims: readers[0] ?? claimsUnread,
	});
}
