import type { ClaimsSelections } from "@mod/claims-selection";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import type { ReleasedClaims } from "@mod/oidc";
import { type RateLimit, sourceKey, type Window } from "@mod/rate-limit";
import { challengeOf, type SenderBindings } from "@mod/sender-binding";
import type { Sessions } from "@mod/session";
import type { SessionTokens } from "@mod/session-tokens";
import type { Tokens } from "@mod/tokens";

export interface UserinfoParts {
	/** Epoch ms, `kernel`'s clock. */
	readonly now: () => number;
	readonly senderBinding: Pick<SenderBindings, "admitted">;
	readonly tokens: Pick<Tokens, "verifyAccess">;
	readonly sessionTokens: Pick<SessionTokens, "sessionOf">;
	readonly sessions: Pick<Sessions, "entryOf">;
	readonly selections: Pick<ClaimsSelections, "forToken">;
	readonly claims: Pick<ReleasedClaims, "of">;
	/** Counts the requests not in the DPoP scheme, per source. */
	readonly counting: Pick<RateLimit, "hit">;
	readonly window: Window;
}

const answer = (status: number, json: unknown, headers: Record<string, string> = {}) =>
	jsonAnswer(status, json, { headers });
/** A check or the claims could not tell: never a refusal, never a claim. */
export const unavailable = answer(503, { error: "temporarily_unavailable" });

/** The name userinfo's per-source window is counted under. */
const countedAs = "userinfo";

/**
 * Whether the request says it is in the DPoP scheme. `dpop` counts a proof by the token's key alone;
 * any other request in that scheme is refused at the token's check, uncounted. A request not in it (a
 * Bearer token, or none) has nothing else counting it.
 */
const inDpopScheme = (request: HttpRequest) =>
	/^dpop /i.test(request.headers.get("authorization") ?? "");

/** Counts a request not in the DPoP scheme by its source: `429` past the window, with its wait. */
async function counted(p: UserinfoParts, request: HttpRequest): Promise<HttpResponse | undefined> {
	if (inDpopScheme(request)) return undefined;
	// A source a trusted proxy did not tell is the deployment's error, never a source of its own to count.
	if (!request.source.determined) throw new Unavailable("undetermined source");
	const hit = await p.counting.hit(countedAs, sourceKey(request.source.address), p.window);
	if (hit.kind === "allowed") return undefined;
	const seconds = String(Math.ceil(hit.retryAfterMs / 1000));
	return answer(429, { error: "rate_limited" }, { "retry-after": seconds });
}

/**
 * Answers the subject of the access token the request presents, and the claims oidc releases for its
 * scope and the selection kept for it, while the session it was issued in enters at use for that
 * subject. A token issued in no session is refused, whatever grant gave it. Throws Unavailable when
 * a check cannot tell.
 */
export function userinfoOver(p: UserinfoParts) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		const limited = await counted(p, request);
		if (limited) return limited;
		const admission = await p.senderBinding.admitted(request, p.tokens);
		if (admission.kind === "refused") {
			const { status, error, headers } = admission;
			return answer(status, error === undefined ? {} : { error }, headers);
		}
		const { id, grant, tokenType, expiresAt } = admission.access;
		// OIDC Core §5.3 serves a token issued for openid; any other is short of scope (RFC 6750 §3.1).
		if (!grant.scope.includes("openid")) {
			return answer(
				403,
				{ error: "insufficient_scope" },
				challengeOf(tokenType, "insufficient_scope"),
			);
		}
		// Challenged in the token's own scheme, as sender-binding challenges a token it refuses.
		const invalid = () =>
			answer(401, { error: "invalid_token" }, challengeOf(tokenType, "invalid_token"));
		const bound = await p.sessionTokens.sessionOf(id);
		// A token issued in no session (a client's own, though its scope names openid) is not a user's
		// to answer for: refused, its subject not told.
		if (bound.kind === "unbound") return invalid();
		const entry = await p.sessions.entryOf(bound.handle);
		if (entry.kind !== "entered" || entry.session.context.subject !== grant.subject)
			return invalid();
		// What the token's request asked beyond its scope, and the constraints on all it releases.
		const selection = await p.selections.forToken(id);
		// Checked again once read: a token still in time had its selection, which outlives it, to read;
		// one that ended meanwhile is refused rather than answered without it.
		if (p.now() >= expiresAt) return invalid();
		const claims = await p.claims.of(grant.subject, grant.scope, bound.handle, selection);
		return answer(200, { ...claims, sub: grant.subject });
	};
}
