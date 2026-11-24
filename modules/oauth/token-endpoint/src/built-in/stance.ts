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
