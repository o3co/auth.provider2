import { type Approvals, approvals, type ItemsOf } from "@mod/approvals";
import { type Clients, clients } from "@mod/clients";
import { type Codes, codeGrantType, codes } from "@mod/code-grant";
import { requestOf } from "@mod/front-core-codec";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { type BuildContext, Unavailable } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import { type Sessions, sessions } from "@mod/session";
import { type AccessTokenIssuance, accessTokenIssuance } from "@mod/tokens";
import {
	type CodeNeeds,
	codeNeedsIn,
	codeNeedsTakes,
	type Unmet,
} from "../code-needs/code-needs.ts";
import { type RequestClaims, requestClaims } from "../contract.ts";

/**
 * How a person's login with a passkey is named in the session and the token (RFC 8176), by what its
 * assertion proves: `pop`, a key held (its signature), and `user`, the person present (its flags). No
 * `hwk` (no attestation is taken; a synced passkey is held by no one device), no `mfa` (verifying the
 * user is the authenticator's own word; strength is `acr`'s to say).
 */
export const passkeyAmr = ["pop", "user"] as const;

export interface FinishParts {
	readonly approvals: Pick<Approvals, "use" | "complete" | "completionOf" | "publish">;
	readonly clients: Pick<Clients, "find">;
	readonly issuance: Pick<AccessTokenIssuance, "admits">;
	readonly sessions: Pick<Sessions, "open" | "close">;
	readonly codes: Pick<Codes, "issue" | "root" | "digestOf" | "lifetimeMs">;
	/** What an OpenID request's `claims` select: the `requestClaims` contributed, else `claimsUnselected`. */
	readonly claims: Pick<RequestClaims, "select">;
	/** What a code needs, checked again before the session opens (internal module `code-needs`). */
	readonly needs: CodeNeeds;
	/** How long a login's delegation lasts from its statement's issue, in seconds (O27). */
	readonly delegationS: number;
	/** The acr a passkey's login meets, by `acr`'s table; none where it meets none. */
	readonly acr?: string;
}

const refused = (status: number, error: string, description: string): HttpResponse =>
	jsonAnswer(status, { error, error_description: description });
const bad = (description: string) => refused(400, "invalid_request", description);
const denied = (description: string) => refused(400, "access_denied", description);

/** A code's need unmet, as the finish answers it before the session opens. */
const unmetAnswer = (unmet: Unmet): HttpResponse => {
	switch (unmet.need) {
		case "grant":
			return bad("the client may not use the code grant");
		case "challenge":
			return bad("the code challenge is malformed");
		case "scope":
			return refused(400, "invalid_scope", "the scope is not allowed");
		case "resource":
			return bad("the resource is not one the client may be issued for");
		case "binding":
			return bad("the statement names no binding asked for ahead");
		default:
			return unmet satisfies never;
	}
};

/** The approval's refusals that are the request's own fault; any other is the person's passkey refused. */
const malformed = new Set(["unknown", "expired", "used", "purpose", "malformed"]);

/**
 * ⑤⑥: the person's assertion over T used once, the issuance judged, the session opened and a code
 * made, the approval put on the subject's flow, the code rooted in that record, and the completion
 * answered, sealed to the screen. A resent finish whose completion is kept is answered it again.
 */
export function finishing(p: FinishParts) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		// Every field held to front-core-wire's spec before any is acted on, as the Front's are.
		const read = requestOf("loginFinish", { values: request.fields, headers: new Map() });
		if (!read.ok) return bad("the finish's fields are not front-core-wire's");
		const { statement, assertion } = read.message;
		const used = await p.approvals.use({ statement, assertion });
		if (used.kind === "refused")
			return malformed.has(used.reason)
				? bad("the statement cannot be used")
				: denied("the login was not approved");
		const { approval } = used;
		if (approval.purpose !== "authorization" || approval.subject === undefined)
			return bad("the statement is no authorization's");
		if (approval.completed) {
			// Given again only once it went out, its code rooted: before that, no second code is made.
			const kept = await p.approvals.completionOf(approval.hash);
			return kept
				? jsonAnswer(200, { sealed: { enc: kept.enc, ct: kept.ct } })
				: refused(503, "temporarily_unavailable", "the login is being finished; ask again");
		}
		const items = approval.items as ItemsOf["authorization"];
		const subject = approval.subject;
		const client = await p.clients.find(items.client_id);
		if (!client) return refused(401, "invalid_client", "no such client");
		// Checked before the session opens, so nothing a code needs fails once the person tapped.
		const met = p.needs.atFinish(client, items);
		if ("need" in met) return unmetAnswer(met);
		const { scope, audience, binding } = met;
		const begunMs = approval.issuedAt;
		const authenticatedAt = approval.usedAt ?? begunMs;
		const grant = {
			subject,
			subjectKind: "user" as const,
			issuedTo: client.id,
			audience,
			scope,
			amr: passkeyAmr,
			authenticatedAt,
		};
		const admitted = await p.issuance.admits({ grant, grantType: codeGrantType });
		if (admitted.kind === "refused") return denied("the login was not approved");
		// An OpenID request's claims, selected before the session opens; a `sub` asked of another refuses it.
		const picked = p.needs.asksOpenid(scope)
			? await p.claims.select(client, subject, items.scope.split(" "), items.claims, p.acr)
			: ({ kind: "none" } as const);
		if (picked.kind === "otherSubject") return denied("the login is not of the subject asked");
		// OpenID Connect Core §5.5.1.1: an essential acr not met is an authentication that failed.
		if (picked.kind === "acrUnmet") return denied("the login does not meet the acr asked");
		const opened = await p.sessions.open({
			subject,
			amr: passkeyAmr,
			authenticatedAt,
			provenSince: begunMs,
			endsAt: begunMs + p.delegationS * 1000,
		});
		if (opened.kind === "revoked") return denied("the login was not approved");
		const handle = opened.session.id;
		// A session opened for a finish that gives no completion is closed again.
		const close = () => p.sessions.close(handle).catch(() => undefined);
		try {
			// Made with no root: its root, the approval's record, carries the code's digest and is placed after.
			const code = await p.codes.issue({
				clientId: client.id,
				redirectUri: items.redirect_uri,
				challenge: items.code_challenge,
				nonce: items.nonce,
				scope,
				audience,
				session: handle,
				subject,
				binding,
				...(p.acr === undefined ? {} : { acr: p.acr }),
			});
			// Pinned to the code before its root is set: a code never rooted is never redeemed.
			if (picked.kind === "selected")
				await picked.keep(p.codes.digestOf(code), p.codes.lifetimeMs(), subject);
			const completed = await p.approvals.complete({ hash: approval.hash, code });
			if (completed.kind === "refused") {
				await close();
				if (completed.reason === "withdrawn")
					return refused(503, "temporarily_unavailable", "the Core cannot sign now");
				return completed.reason === "expired" || completed.reason === "unknown"
					? bad("the statement cannot be used")
					: denied("the login was not approved");
			}
			// Rooted before the completion goes out, with what the approval gives an ID token; one never
			// rooted is never redeemed.
			const named = {
				esig: approval.esig,
				apr: completed.ref,
				approvedAt: completed.acceptedAt,
				// Its statement's hash, which a refresh family rests on (`approvals`' `rootOf`).
				statement: approval.hash,
			};
			if ((await p.codes.root(code, completed.record, named)) !== "set")
				throw new Unavailable("authorize");
			// Published after: a resend is given it only now. One whose publishing failed is answered
			// here all the same, its code rooted; a resend of it is told to ask again.
			await p.approvals.publish(approval.hash).catch(() => undefined);
			return jsonAnswer(200, { sealed: { enc: completed.enc, ct: completed.ct } });
		} catch (error) {
			await close();
			throw error;
		}
	};
}

/** The contracts the finish takes, for the module to declare. */
export const finishTakes = [
	approvals,
	clients,
	accessTokenIssuance,
	sessions,
	...codeNeedsTakes,
	requestClaims,
] as const;

/**
 * Where no module reads a request's `claims`, none are selected: the start refused any, so a T
 * carrying them past ② was let through elsewhere, a `TypeError` rather than a code unchecked.
 */
export const claimsUnselected: FinishParts["claims"] = {
	select: async (_client, _subject, _scope, claims) => {
		if (claims !== undefined) throw new TypeError("authorize: claims past ② that no module reads");
		return { kind: "none" };
	},
};

/** The route of ⑤⑥, its parts taken from the composition, counted per source. */
export async function finishRoute(
	c: Pick<BuildContext<unknown>, "get" | "collect">,
	p: {
		readonly issuer: string;
		readonly delegationS: number;
		readonly window: Window;
		readonly acr: string | undefined;
	},
) {
	return {
		method: "POST" as const,
		path: "/login/finish",
		uses: [use(requestsPerSource, { name: "authorize.finish", window: p.window })],
		takes: ["json" as const],
		cors: { headers: ["content-type"] },
		crossSite:
			"The screen's request reads no cookie; what it finishes is bound to the statement and the person's assertion over it.",
		handle: finishing({
			approvals: await c.get(approvals),
			clients: await c.get(clients),
			issuance: await c.get(accessTokenIssuance),
			sessions: await c.get(sessions),
			codes: await c.get(codes),
			claims: (await c.collect(requestClaims))[0] ?? claimsUnselected,
			needs: await codeNeedsIn(c, p.issuer),
			delegationS: p.delegationS,
			...(p.acr === undefined ? {} : { acr: p.acr }),
		}),
	};
}
