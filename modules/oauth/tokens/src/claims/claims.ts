import type { AccessGrant, Actor, ClaimClass, SubjectKind } from "../contract.ts";

/**
 * The access token's claims tokens writes, closed: any other is a claim a grant adds, under
 * `added-claims`' rules, which is outside the monitor's check.
 */
export const accessTokenClaims: Readonly<Record<string, ClaimClass>> = Object.freeze({
	iss: "derived",
	sub: "evidence",
	o3co_subject_kind: "derived",
	client_id: "evidence",
	aud: "evidence",
	scope: "evidence",
	cnf: "evidence",
	act: "evidence",
	amr: "derived",
	acr: "derived",
	auth_time: "derived",
	o3co_standing_at: "derived",
	iat: "derived",
	exp: "derived",
	jti: "derived",
	txr: "outside",
});

/** Whether a name is one tokens writes, whether or not added-claims reserves it. */
export const inTable = (name: string) => Object.hasOwn(accessTokenClaims, name);

const subjectKinds: readonly unknown[] = ["user", "client"] satisfies SubjectKind[];

/**
 * Throws TypeError, the caller's mistake, on a grant saying no subject kind, on a client's token
 * for another subject than its client, and on added claims taking a name of the table.
 */
export function checkClaims(grant: Omit<AccessGrant, "claims">, added: object | undefined) {
	if (!subjectKinds.includes(grant.subjectKind)) throw new TypeError("tokens: no subject kind");
	// A client's token stands for the client itself: its subject is the client it is issued to.
	if (grant.subjectKind === "client" && grant.subject !== grant.issuedTo) {
		throw new TypeError("tokens: a client's token names the client it is issued to as its subject");
	}
	const taken = Object.keys(added ?? {}).filter(inTable);
	if (taken.length > 0) throw new TypeError(`tokens: a claim tokens writes is added: ${taken[0]}`);
}

type Act = { readonly sub: string; readonly act?: Act };
const actOf = (actor: Actor): Act => ({
	sub: actor.subject,
	...(actor.actor ? { act: actOf(actor.actor) } : {}),
});

/** A kept grant as claims; the added ones, `act`, `amr`, `auth_time` and `acr` only when given. */
export const grantClaims = (grant: AccessGrant) => ({
	// None can stand for a name below: a grant adds no name of the table.
	...grant.claims,
	sub: grant.subject,
	o3co_subject_kind: grant.subjectKind,
	aud: grant.audience.length === 1 ? grant.audience[0] : grant.audience,
	client_id: grant.issuedTo,
	...(grant.scope.length > 0 ? { scope: grant.scope.join(" ") } : {}),
	...(grant.actor ? { act: actOf(grant.actor) } : {}),
	...(grant.amr ? { amr: grant.amr } : {}),
	...(grant.authenticatedAt === undefined || grant.authenticatedAtUnknown
		? {}
		: { auth_time: grant.authenticatedAt / 1000 }),
	...(grant.acr === undefined ? {} : { acr: grant.acr }),
});
