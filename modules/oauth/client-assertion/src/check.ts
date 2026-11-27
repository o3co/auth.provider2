import type { Reason } from "@mod/external-jwt";

/** `external-jwt`'s reasons, in the words this module logs. */
export const said: Readonly<Record<Reason, string>> = {
	malformed: "not a JWT",
	typ: "not of the typ asked",
	"no-exp": "no exp that is a time",
	"time-claim": "nbf or iat is not a time",
	algorithm: "algorithm",
	"no-key": "no key fits",
	"ambiguous-key": "more than one key fits",
	signature: "signature",
	expired: "expired",
	"not-yet": "not yet valid",
	"future-iat": "issued in the future",
	"too-long": "lives too long",
	issuer: "issuer",
	audience: "audience",
	// `iss` and `sub` are both the client's id, so a wrong subject is a wrong issuer.
	subject: "issuer",
};

/** One word for every way a JWT is not the client's by its signature. */
const unsigned = "not signed by the client";

/**
 * The words `verifySignedBy` answers, which a caller may tell the JWT's sender: each says nothing
 * beyond the JWT itself and the policy asked. The sender may be anyone, so whether the client holds a
 * key the JWT names is never told apart from a signature that does not verify.
 */
export const told: Readonly<Record<Reason, string>> = {
	// Each its own entry, not the log's by default: a reason added is answered only once it is judged safe to tell.
	malformed: said.malformed,
	typ: said.typ,
	"no-exp": said["no-exp"],
	"time-claim": said["time-claim"],
	algorithm: said.algorithm,
	"no-key": unsigned,
	"ambiguous-key": unsigned,
	signature: unsigned,
	expired: said.expired,
	"not-yet": said["not-yet"],
	"future-iat": said["future-iat"],
	"too-long": said["too-long"],
	issuer: said.issuer,
	audience: said.audience,
	subject: said.subject,
};
