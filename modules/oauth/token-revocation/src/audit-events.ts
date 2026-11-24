import { auditEvents } from "@mod/audit";

/** What token revocation records; a revocation never holds the token. */
export default auditEvents({
	"token.revoked": {
		attributes: ["client", "source", "token_type"],
		when: "a revocation is written; `token_type` is the kind's hint",
	},
});
