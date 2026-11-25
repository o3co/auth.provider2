import { claimsSelections } from "@mod/claims-selection";
import { type Route, routes } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { releasedClaims } from "@mod/oidc";
import { promiseNames, stances } from "@mod/promises";
import { rateLimit } from "@mod/rate-limit";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
import { accessTokens } from "@mod/tokens";
import { section } from "./section.ts";
import { unavailable, userinfoOver } from "./userinfo.ts";

const path = "/oauth/userinfo";

/** A page may send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait. */
const cors = {
	headers: ["authorization", "dpop", "content-type"],
	exposes: ["www-authenticate", "dpop-nonce", "retry-after"],
};

/** Why answering userinfo breaks the promise of a new authorization (claim 1, G1). */
const newAuthorization =
	"a userinfo answer is bound to neither the token nor the request, so the Front can answer any sub and attributes: a relying party that trusts it trusts the Front that relays it";
/** Why it breaks the promise of a client's token (claim 2, G1). */
const clientToken =
	"a userinfo answer is bound to neither the token nor the request: a party that takes it in place of checking the token trusts the Front that relays it";

/** The handler; a check or claims that cannot tell throw Unavailable, which the route answers. */
async function handlerOf(
	c: BuildContext<{ requests: number; window: number }>,
): Promise<Route["handle"]> {
	return userinfoOver({
		now: c.clock.now,
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(accessTokens),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
		selections: await c.get(claimsSelections),
		claims: await c.get(releasedClaims),
		counting: await c.get(rateLimit),
		window: { limit: c.section.requests, ms: c.section.window * 1000 },
	});
}

/** What its routes and its metadata take. */
const takes = [
	senderBinding,
	accessTokens,
	sessionTokens,
	sessions,
	claimsSelections,
	releasedClaims,
	rateLimit,
	issuer,
];

export default defineModule({ name: "userinfo", replicaSafe: true, section, takes }, (m) => [
	...(["GET", "POST"] as const).map((method) =>
		m.contribute(routes).by(async (c) => ({
			method,
			path,
			cors,
			// A POST may carry a body, but the token is read from the header only.
			takes: ["form", "json", "none"],
			...(method === "GET"
				? { changesState: false }
				: {
						crossSite:
							"The access token comes in the Authorization header, never a cookie, and it only reads.",
						unlimited:
							"It only reads, and counts by source in its own handler any request not in the DPoP scheme; `dpop` counts a proof by the token's key alone, and any other request in that scheme is refused at the token's check, uncounted.",
					}),
			// `503`, never a refusal: http warns of it once, by what failed and the route.
			unavailable: { response: unavailable },
			handle: await handlerOf(c),
		})),
	),
	m.contribute(metadata).by(async (c) => ({
		name: "userinfo_endpoint",
		value: new URL(path, (await c.get(issuer)).endpointOrigin).href,
	})),
	m.contribute(stances).by(() => ({
		promise: promiseNames.newAuthorization,
		holds: false,
		by: "userinfo",
		reason: newAuthorization,
	})),
	m.contribute(stances).by(() => ({
		promise: promiseNames.clientToken,
		holds: false,
		by: "userinfo",
		reason: clientToken,
	})),
]);
