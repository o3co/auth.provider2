import type { Reason } from "@mod/external-jwt";

/** `external-jwt`'s reasons, in the words this module logs. */
export const said: Readonly<Record<Reason, string>> = {
	malformed: "not a JWT",
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
