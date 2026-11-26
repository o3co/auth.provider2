import { type Grant, grantServers } from "@mod/grants";
import { promiseNames, type Stance } from "@mod/promises";

/** Where the token endpoint stands, as issuing access tokens asks of its taker: each bundle is recorded before any of it is signed. */
export const tokenEndpointStance: Stance = Object.freeze({
	promise: promiseNames.coreContained,
	holds: true,
	by: "token-endpoint",
});

/** Why a grant breaks the promise that no client subject token is issued; none for one declaring a person's. */
const breaking = ({ grantType, subjectKind }: Pick<Grant, "grantType" | "subjectKind">) => {
	if (subjectKind === "user") return [];
	const server = grantServers[grantType];
	const named = server === undefined ? grantType : `${grantType} (${server})`;
	return subjectKind === "client"
		? [
				`${named} issues a token whose subject is the client, on its key alone, with no user's approval at its root`,
			]
		: [`${named} declares no subject kind`];
};

/**
 * Where the token endpoint stands on `no-client-subject-token`, from the subject kind each grant
 * composed declares: held where every one declares a person's, broken by any other, named.
 */
export const clientSubjectStance = (
	composed: readonly Pick<Grant, "grantType" | "subjectKind">[],
): Stance => {
	const reasons = composed.flatMap(breaking);
	return Object.freeze({
		promise: promiseNames.noClientSubjectToken,
		holds: reasons.length === 0,
		by: "token-endpoint",
		...(reasons.length === 0 ? {} : { reason: reasons.join("; ") }),
	});
};

/** What each hold a grant declares rests on, in the endpoint's words. */
const holdOf: Readonly<Record<NonNullable<Grant["keyHold"]>, string>> = {
	authorization: "the key its client's signed authorization named ahead",
	family: "its family's key",
	assertion: "the key that signed the client's assertion, proved by that key",
};
/** The hold a grant declares, or none: a value no hold is counts as none, never as one. */
const holdOfGrant = ({ keyHold }: Pick<Grant, "keyHold">): string | undefined =>
	typeof keyHold === "string" && Object.hasOwn(holdOf, keyHold) ? holdOf[keyHold] : undefined;

/**
 * Where the token endpoint stands on `front-compromise-client-token` (claim 2), from how each grant
 * composed declares it holds a client's tokens to a key: held where every one declares a hold, its
 * reason what each rests on; broken by any declaring none, its grant type named. The authentication
 * methods' keys are `clients`' to judge.
 */
export const keyHoldStance = (
	composed: readonly Pick<Grant, "grantType" | "keyHold">[],
): Stance => {
	const silent = composed.filter((g) => holdOfGrant(g) === undefined).map((g) => g.grantType);
	if (silent.length > 0)
		return Object.freeze({
			promise: promiseNames.clientToken,
			holds: false,
			by: "token-endpoint",
			reason: `${silent.join(", ")} declares no hold of a client's tokens to a key`,
		});
	const held = composed.map((g) => `${g.grantType}: ${holdOfGrant(g)}`);
	return Object.freeze({
		promise: promiseNames.clientToken,
		holds: true,
		by: "token-endpoint",
		...(held.length === 0 ? {} : { reason: held.join("; ") }),
	});
};
