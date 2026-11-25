import { type ClaimsSelections, claimsSelections } from "@mod/claims-selection";
import type { Client } from "@mod/clients";
import type { Grant, GrantOutcome } from "@mod/grants";
import { type BuildContext, sameSecret, Unavailable } from "@mod/kernel";
import { type Keys, keys } from "@mod/keys";
import { challengeInput, payloads, typs } from "@mod/sdk-core-wire";
import { sameBinding } from "@mod/sender-binding";
import { type Sessions, sessions } from "@mod/session";
import type { RevocableKind, Revoked } from "@mod/token-revocation";
import { accessTokens, referenceOf, type Tokens } from "@mod/tokens";
import { type Ceremonies, ceremonies } from "@mod/webauthn";
import { refreshGrantType } from "../contract.ts";
import {
	type FamilyRecord,
	live,
	nameOf,
	read,
	revokeFamily,
	sha256,
	tokenParts,
} from "../record.ts";
import { type FamilyRecords, familyRecords } from "../store.ts";

/** What the refresh grant is made over. */
export interface GrantParts {
	readonly records: FamilyRecords;
	readonly keys: Pick<Keys, "verifyOf">;
	readonly ceremonies: Pick<Ceremonies, "reverifyAssertion">;
	readonly sessions: Pick<Sessions, "entryOf">;
	/** Revoking a token issued while its session closed. */
	readonly tokens: Pick<Tokens, "revokeReferenced">;
	readonly selections: Pick<ClaimsSelections, "forRefreshed">;
	/** The delegation's length, in ms (O27). */
	readonly lifetimeMs: number;
	readonly now: () => number;
}

/** One answer for every refused token, so it tells nothing about why. */
const refused: GrantOutcome = {
	kind: "error",
	error: "invalid_grant",
	description: "invalid refresh token",
};
const malformed = (description: string): GrantOutcome => ({
	kind: "error",
	error: "invalid_request",
	description,
});
/** The token endpoint's refusal of a family its flow's state does not hold. */
const isEndedFamily = (r: { readonly policy: string; readonly reason: string }) =>
	r.policy === "token-endpoint" && r.reason === "family";

/** Offline access is not offered: no part of a grant. */
const offlineAccess = "offline_access";

/** A live family by its token, of this client: its record and id; none for any other. */
async function familyOf(p: GrantParts, token: string, client: Client) {
	const parts = tokenParts(token);
	if (!parts) return undefined;
	const r = read.family(await p.records.read(nameOf.family(parts.family)));
	if (!live(r, p.now()) || r.client !== client.id) return undefined;
	return sameSecret(sha256(parts.secret), r.secret) ? { id: parts.family, record: r } : undefined;
}

/**
 * The family's root checked again (proposal 3.9), never the Store's word for it: its statement by the
 * Core ring of the generation that signed it, of this client and the family's key, its assertion by
 * the key the family recorded, the family's scope within it and its end within its delegation.
 */
async function rooted(p: GrantParts, r: FamilyRecord, client: Client): Promise<boolean> {
	const verified = await p.keys.verifyOf(r.generation, r.statement, typs.statement);
	if (verified.kind !== "valid") return false;
	const t = payloads.statement.safeParse(verified.claims);
	if (!t.success) return false;
	const { approval, iat } = t.data;
	if (approval.client_id !== client.id || approval.dpop_jkt !== r.binding.confirmation)
		return false;
	const words = approval.scope.split(" ");
	if (!r.scope.every((word) => words.includes(word))) return false;
	// The resource it asked is the family's one audience (RFC 8707), as the code was issued for it.
	if (
		approval.resource !== undefined &&
		(r.audience.length !== 1 || r.audience[0] !== approval.resource)
	)
		return false;
	if (r.end > iat * 1000 + p.lifetimeMs) return false;
	const challenge = sha256(challengeInput(r.statement, "get"));
	return (
		p.ceremonies.reverifyAssertion(r.assertion, r.publicKey, challenge)?.credential === r.credential
	);
}

/** The scope a round asks: within the family's, each word once; all of it where none is asked. */
function scopeAsked(asked: string | undefined, family: readonly string[]) {
	if (asked === undefined || asked === "") {
		const all = family.filter((word) => word !== offlineAccess);
		return all.length > 0 ? all : undefined;
	}
	const words = asked.split(" ");
	if (words.some((word) => word === "") || new Set(words).size !== words.length) return undefined;
	const kept = words.filter((word) => word !== offlineAccess);
	if (kept.length === 0 || !kept.every((word) => family.includes(word))) return undefined;
	return kept;
}

/** The refresh grant (RFC 6749 §6), over a family rooted in its approval: never rotated. */
export function refreshGrant(p: GrantParts): Grant {
	return {
		grantType: refreshGrantType,
		readsAmbient: "none",
		targets: true,
		subjectKind: "user",
		handle: async ({ client, param, binding, admits, issue, target }) => {
			const token = param("refresh_token");
			if (!token) return malformed("refresh_token is required");
			const found = await familyOf(p, token, client);
			// Bound to its key: a proof by another, or none, is refused (sender-binding's sameBinding).
			if (!found || !sameBinding(binding, found.record.binding)) return refused;
			const r = found.record;
			if (!(await rooted(p, r, client))) return refused;
			const entry = await p.sessions.entryOf(r.session);
			if (entry.kind !== "entered") return refused;
			const scope = scopeAsked(param("scope"), r.scope);
			if (!scope)
				return {
					kind: "error",
					error: "invalid_scope",
					description: "the scope is not the family's",
				};
			const asked = target(r.audience, (audience) => r.audience.includes(audience));
			if (asked.kind === "error") return asked;
			const access = {
				subject: r.subject,
				subjectKind: "user" as const,
				issuedTo: client.id,
				audience: asked.audience,
				scope,
				amr: r.amr,
				authenticatedAt: r.authTime,
				...(r.acr === undefined ? {} : { acr: r.acr }),
			};
			const from = { session: r.session, continuing: true as const };
			const admitted = await admits(access, from);
			if (admitted.kind === "refused") return admitted;
			const issued = await issue(
				{ root: found.id, via: { via: "refresh" }, access },
				{ ...from, notAfter: Math.min(r.end, entry.endsAt) },
			);
			// A family the flow's state no longer holds is refused as every token is.
			if (issued.kind === "refused") return isEndedFamily(issued.refusal) ? refused : issued;
			// Read again after issuing and recording (proposal 3.15, 1): a close racing them found no
			// token to end, so one closed meanwhile has its token revoked here, and none answered.
			if ((await p.sessions.entryOf(r.session)).kind !== "entered") {
				const revoked = await p.tokens.revokeReferenced(referenceOf(issued.access));
				// Answered to none, the token needs no list to revoke it later: it never left this process.
				if (revoked.kind === "unsupported") throw new Unavailable("refresh");
				return refused;
			}
			const { id, expiresAt } = issued.access;
			await p.selections.forRefreshed(found.id, client, r.subject, { id, expiresAt });
			return {
				kind: "issued",
				body: {
					access_token: issued.access.token,
					token_type: issued.access.tokenType,
					expires_in: issued.access.expiresIn,
					scope: scope.join(" "),
					// Bound to its key, the family is never rotated (proposal 3.9): its one token again.
					refresh_token: token,
				},
			};
		},
	};
}

/** `refresh_token` revoked by its own client, with its whole family (RFC 7009); any other is done. */
export function revocableFamilies(p: Pick<GrantParts, "records" | "now">): RevocableKind {
	return {
		hint: refreshGrantType,
		revoke: async (token, client): Promise<Revoked> => {
			const parts = tokenParts(token);
			if (!parts) return "unknown";
			const r = read.family(await p.records.read(nameOf.family(parts.family)));
			if (!r || !sameSecret(sha256(parts.secret), r.secret)) return "unknown";
			if (r.client !== client.id) return "done";
			await revokeFamily(p.records, parts.family);
			return "written";
		},
	};
}

/** What the grant takes from the composition. */
export const grantTakes = [
	familyRecords,
	keys,
	ceremonies,
	sessions,
	accessTokens,
	claimsSelections,
] as const;

export const grantIn = async (
	c: Pick<BuildContext<unknown>, "get" | "clock">,
	lifetimeMs: number,
) => {
	const records = await c.get(familyRecords);
	const parts: GrantParts = {
		records,
		keys: await c.get(keys),
		ceremonies: await c.get(ceremonies),
		sessions: await c.get(sessions),
		tokens: await c.get(accessTokens),
		selections: await c.get(claimsSelections),
		lifetimeMs,
		now: c.clock.now,
	};
	return { grant: refreshGrant(parts), revocable: revocableFamilies(parts) };
};
