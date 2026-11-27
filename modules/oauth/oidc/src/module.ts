import { claimScopes, claimsSelections } from "@mod/claims-selection";
import { idTokens, openid } from "@mod/code-grant";
import { issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { keys } from "@mod/keys";
import { promiseNames, stances } from "@mod/promises";
import { subjectAttributes } from "@mod/subject-attributes";
import { releasedOver, scopeOfClaim, tableClaims, tableScopes } from "./claims/claims.ts";
import { idTokenHints, releasedClaims } from "./contract.ts";
import { hintReader } from "./hint/hint.ts";
import { idTokenMaker } from "./id-token/id-token.ts";
import { section } from "./section.ts";

/**
 * The algorithms of SHA-256, for now the only ones an ID token is signed by: its `c_hash` is the left
 * half of its algorithm's hash, and the log names a code by its SHA-256 alone (A21). Held until the
 * log's code digest is of each algorithm's hash (a wire change, the owner's to decide).
 */
const ofSha256 = new Set(["ES256", "RS256", "PS256"]);
const refusal = (alg: string) =>
	`an ID token's c_hash is of SHA-256, and the authority's ring signs with ${alg}: with openid composed, set the authority's ring to an algorithm of SHA-256 (ES256, RS256 or PS256)`;

const takes = [keys, issuer, subjectAttributes, claimsSelections];

export default defineModule({ name: "oidc", replicaSafe: true, section, takes }, (m) => [
	m.contribute(stances).by(() => ({
		promise: promiseNames.coreContained,
		holds: false,
		by: "oidc",
		reason: "an ID token carries no receipt of the transparency log",
	})),
	m.contribute(idTokens).by(async (c) => {
		const signing = await c.get(keys);
		const alg = signing.algorithm("authority");
		if (!ofSha256.has(alg)) return c.refuse("oidc", refusal(alg));
		const next = signing.nextAlgorithm("authority");
		// Promoted, a next key of another hash would refuse the next boot: said at each boot until then.
		if (next !== undefined && !ofSha256.has(next))
			c.log.warn("oidc.next_key_alg_refused", { alg: next });
		const attributes = await c.get(subjectAttributes);
		const selections = await c.get(claimsSelections);
		return idTokenMaker({
			keys: signing,
			issuer: (await c.get(issuer)).url,
			lifetimeS: c.section["id-token-lifetime"],
			attributes: async (subject, session) => {
				const answer = await attributes.of(subject, session);
				return answer.kind === "known" ? answer : undefined;
			},
			asked: async (code) => (await selections.forCode(code))?.idToken,
		});
	}),
	m.provide(releasedClaims).by(async (c) => {
		const attributes = await c.get(subjectAttributes);
		return {
			of: async (subject, scope, session, asked) => {
				const answer = await attributes.of(subject, session);
				return releasedOver(answer.kind === "known" ? answer : undefined, scope, asked);
			},
		};
	}),
	m.provide(idTokenHints).by(async (c) => {
		const signing = await c.get(keys);
		return hintReader({
			verify: (ring, token, typ) => signing.verify(ring, token, typ),
			issuer: (await c.get(issuer)).url,
		});
	}),
	m.contribute(claimScopes).by(() => ({ scopeOf: scopeOfClaim })),
	m.contribute(metadata).by(() => ({ name: "scopes_supported", value: [openid, ...tableScopes] })),
	m.contribute(metadata).by(() => ({ name: "claims_supported", value: ["sub", ...tableClaims] })),
	m.contribute(metadata).by(() => ({ name: "subject_types_supported", value: ["public"] })),
	m.contribute(metadata).by(async (c) => ({
		name: "id_token_signing_alg_values_supported",
		value: [(await c.get(keys)).algorithm("authority")],
	})),
]);
