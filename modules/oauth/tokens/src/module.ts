import { addedClaimsWith } from "@mod/added-claims";
import { issuer, metadata } from "@mod/issuer";
import { contract, defineModule, Unavailable } from "@mod/kernel";
import { accessTokenSigning } from "@mod/keys";
import { promiseNames, stances } from "@mod/promises";
import { senderBinding } from "@mod/sender-binding";
import { denylistAllowanceMs, denylistOver, revokedTokens } from "@mod/token-denylist";
import { grantClaims } from "./claims/claims.ts";
import {
	accessConditions,
	accessTokenIssuance,
	accessTokens,
	issuanceFences,
	issuanceFencing,
	issuancePolicies,
	subjectChecks,
} from "./contract.ts";
import { fencingOver } from "./fencing/fencing.ts";
import {
	type BuiltTokens,
	checkingOf,
	issuanceOf,
	issuing,
	judging,
	type MakeAccess,
} from "./issuance/issuance.ts";
import { compactLength, expiryOf, keptGrant, lifetimeOf, tokenId } from "./limits.ts";
import { namedBy } from "./reference.ts";
import { section } from "./section.ts";
import { standingOf } from "./standing/standing.ts";
import { checkingWith, compactLimit } from "./verification/verification.ts";

/** The one access tokens built, which both handles hand on. */
const built = contract<BuiltTokens>("tokens.built");

/** Whether the section keeps revoked access tokens in a denylist, which takes token-denylist's store. */
const denylisted = (s: { readonly revocation: "denylist" | "unsupported" }) =>
	s.revocation === "denylist";

export default defineModule(
	{
		name: "tokens",
		replicaSafe: true,
		section,
		takes: (s) => [
			accessTokenSigning,
			senderBinding,
			subjectChecks,
			accessConditions,
			issuer,
			issuancePolicies,
			issuanceFences,
			...(denylisted(s) ? [revokedTokens] : []),
		],
	},
	(m) => [
		// keys-publish writes the key set as jwks.json, which the publisher serves under the issuer's
		// own URL, beside the discovery document's place: the issuer's static origin, not the Front's.
		m.contribute(metadata).by(async (c) => ({
			name: "jwks_uri",
			value: `${(await c.get(issuer)).url}/jwks.json`,
		})),
		m.contribute(stances).by(() => ({
			promise: promiseNames.coreContained,
			holds: false,
			by: "tokens",
			reason: "an access token carries no receipt of the transparency log",
		})),
		m
			.provide(issuanceFencing)
			.by(async (c) => fencingOver(await c.collect(issuanceFences), c.random)),
		m.provide(built).by(async (c) => {
			const signing = await c.get(accessTokenSigning);
			const bindings = await c.get(senderBinding);
			const subjects = await c.collect(subjectChecks);
			// Exactly one module checks subject revocation, or the operator states that none does.
			const unchecked = c.section["subject-check"] === "none";
			if (unchecked && subjects.length > 0) {
				return c.refuse(
					"tokens.subject-check",
					"the section states that subjects are not checked, yet a module checks them",
				);
			}
			if (!unchecked && subjects.length !== 1) {
				return c.refuse(
					"tokens.subject-check",
					"needs exactly one module that checks subject revocation, or the section stating none",
				);
			}
			// The operator's choices, yet said at every start: a revoked subject's tokens live on; no
			// access token issued can be revoked.
			if (unchecked) {
				c.log.warn("tokens.subjects_unchecked", {
					reason: "a revoked subject's access tokens are taken until they expire",
				});
			}
			if (!denylisted(c.section)) {
				c.log.warn("tokens.revocation_unsupported", {
					reason: "an access token issued cannot be revoked before it expires",
				});
			}
			const conditions = [...(await c.collect(accessConditions)), ...subjects];
			const denylist = denylistOver(
				denylisted(c.section) ? await c.get(revokedTokens) : undefined,
				c.clock,
			);
			const iss = (await c.get(issuer)).url;
			const lifetime = c.section["access-token-lifetime"];

			const added = addedClaimsWith(c.section["added-claims"]);
			const check = checkingWith({
				signing,
				bindings,
				iss,
				now: c.clock.now,
				readBack: added.readBack,
			});

			const timeout = c.section["issuance-timeout"];
			const judge = judging(await c.collect(issuancePolicies), c.clock.now, () =>
				AbortSignal.timeout(timeout),
			);
			const make: MakeAccess = (grant, askedAt, limits) => {
				const lifetimeSeconds = lifetimeOf(limits?.lifetimeSeconds, lifetime);
				const { iat, exp } = expiryOf(askedAt, lifetimeSeconds, limits?.notAfter);
				const standing = standingOf(grant, iat);
				const claims = {
					iss,
					...grantClaims(keptGrant(grant, iat)),
					...(standing === undefined ? {} : { o3co_standing_at: standing }),
					iat,
					exp,
					jti: tokenId(c.random),
					...(limits?.binding
						? { cnf: { [limits.binding.member]: limits.binding.confirmation } }
						: {}),
				};
				const prepared = signing.prepare();
				const claimsText = JSON.stringify(claims);
				// Its standard claims have no cap of their own: one that would pass what tokens reads once
				// signed is never made, but refused, the operator told its size and the names of the claims
				// a grant added.
				const length = compactLength(prepared.headerText, claimsText, prepared.signatureLength);
				if (length > compactLimit) {
					c.log.warn("tokens.token_too_large", {
						length,
						limit: compactLimit,
						claims: Object.keys(grant.claims ?? {})
							.sort()
							.join(","),
					});
					return { kind: "too-large" as const };
				}
				return {
					headerText: prepared.headerText,
					claimsText,
					signed: async () => {
						const signed = await signing.sign(prepared, new TextEncoder().encode(claimsText));
						// The keys' holder no longer lets this Core sign: nothing can be issued.
						if (signed.kind === "withdrawn") throw new Unavailable("tokens");
						const token = signed.jws;
						// Nothing kept: a token is signed and handed back, no store or record written.
						return {
							access: {
								token,
								id: claims.jti,
								expiresAt: exp * 1000,
								expiresIn: exp - iat,
								tokenType: limits?.binding?.tokenType ?? "Bearer",
								...(grant.claims
									? { addedClaims: Object.freeze(Object.keys(grant.claims).sort()) }
									: {}),
							},
						};
					},
				};
			};
			const access: BuiltTokens = {
				revocable: () => denylist.revocable,
				accessTokenLifetimeSeconds: () => lifetime,
				subjectsChecked: () => !unchecked,
				...issuing(judge, make, c.clock.now, added.of),
				verifyAccess: async (token) => {
					const checked = await check(token);
					if (checked.kind === "invalid") return checked;
					if (await denylist.holds(checked.access.id)) {
						return { kind: "invalid", reason: "revoked" };
					}
					const issuedFor = {
						id: checked.access.id,
						subject: checked.access.grant.subject,
						subjectKind: checked.access.grant.subjectKind,
						issuedAt: checked.issuedAt,
						standingAt: checked.access.standingAt,
					};
					for (const condition of conditions) {
						if ((await condition.holds(issuedFor)) === "revoked") {
							return { kind: "invalid", reason: "revoked" };
						}
					}
					return checked.access;
				},
				issuedToOf: async (token) => {
					const checked = await check(token, denylistAllowanceMs);
					return checked.kind === "invalid"
						? { kind: "invalid" }
						: { kind: "issued", issuedTo: checked.access.grant.issuedTo };
				},
				revokeReferenced: async (reference) => {
					const referenced = namedBy(reference);
					return referenced
						? denylist.revoke(referenced.id, referenced.expiresAt)
						: { kind: "invalid" };
				},
				revokeAccess: async (token) => {
					if (!denylist.revocable) return { kind: "unsupported" };
					// A host whose clock is behind may still take a just-expired token as valid.
					const checked = await check(token, denylistAllowanceMs);
					if (checked.kind === "invalid") return { kind: "invalid" };
					return denylist.revoke(checked.access.id, checked.access.expiresAt);
				},
			};
			return access;
		}),
		m.provide(accessTokens).by(async (c) => checkingOf(await c.get(built))),
		m.provide(accessTokenIssuance).by(async (c) => issuanceOf(await c.get(built))),
	],
);
