import { refusals } from "@mod/front-core-wire";
import type { OAuthError } from "@mod/grants";
import { expect, it } from "vitest";

// Every word the token endpoint answers a refusal with: the grants' OAuth errors (its own among them:
// invalid_request, invalid_grant, unauthorized_client, unsupported_grant_type), an unavailable grant's
// temporarily_unavailable, DPoP's binding words and the per-source limit's. Each must be a word the
// Front's wire carries, or core-wire answers it server_error. One missing from `refusals` makes this
// file fail to typecheck. A grant's own word (GrantOutcome's error is open: OAuthError or any text)
// is not caught here: a grant that answers one names it in this list.
type Answered =
	| OAuthError
	| "temporarily_unavailable"
	| "invalid_dpop_proof"
	| "use_dpop_nonce"
	| "rate_limited";
type Carried = (typeof refusals)[number];
const missing: Record<Exclude<Answered, Carried>, never> = {};
const answered = {
	invalid_request: true,
	invalid_client: true,
	invalid_grant: true,
	unauthorized_client: true,
	unsupported_grant_type: true,
	invalid_scope: true,
	invalid_target: true,
	temporarily_unavailable: true,
	invalid_dpop_proof: true,
	use_dpop_nonce: true,
	rate_limited: true,
} as const satisfies Record<Answered, true>;

it("answers only refusals the Front's wire carries", () => {
	expect(missing).toEqual({});
	for (const word of Object.keys(answered)) expect(refusals, word).toContain(word);
});
