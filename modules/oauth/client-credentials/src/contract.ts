import { clientAllowance } from "@mod/client-allowance";
import type { ClientAssertion } from "@mod/client-assertion";
import type { Grant } from "@mod/grants";
import type { RateLimit } from "@mod/rate-limit";

/** The grant type it serves (RFC 6749 §4.4). */
export const clientCredentialsGrantType = "client_credentials";

/** The binding member a DPoP proof's key confirms a token by: its JWK SHA-256 thumbprint (RFC 9449 §6). */
export const dpopMember = "jkt";

/** The window a client's requests are counted in. */
const window = { name: "client-credentials", ms: 60_000 };

/** How long a token it issues lives, how often a client is issued, and the clients the operator suspended. */
export interface Limits {
	/** Within the fifteen minutes `authority-rules` lets a client's own token live. */
	readonly lifetimeSeconds: number;
	readonly counting: Pick<RateLimit, "hit">;
	/** Requests a client may make in a minute. */
	readonly requests: number;
	readonly suspended: readonly string[];
}

/**
 * The client credentials grant at `issuer`: a confidential client of a version its publisher signed
 * takes a token for itself, within its own ceiling, in one bundle on its own flow, authenticated by
 * a key written in its record and bound to that key by DPoP (`keys`); counted by client (`limits`).
 */
export function clientCredentials(
	issuer: string,
	keys: Pick<ClientAssertion, "verifiedOf">,
	limits: Limits,
): Grant {
	return {
		grantType: clientCredentialsGrantType,
		readsAmbient: "none",
		targets: true,
		subjectKind: "client",
		handle: async ({ client, param, binding, authenticated, issue, target }) => {
			if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
			if (limits.suspended.includes(client.id)) {
				const description = "the client is suspended";
				return { kind: "error", error: "unauthorized_client", description };
			}
			// Counted once authenticated, so no one else can use up a client's requests; Unavailable
			// when it cannot count, never let through.
			const limit = { limit: limits.requests, ms: window.ms };
			const counted = await limits.counting.hit(window.name, client.id, limit);
			if (counted.kind === "limited") {
				const { retryAfterMs } = counted;
				return { kind: "error", error: "rate_limited", status: 429, retryAfterMs };
			}
			const verified = keys.verifiedOf(authenticated, client);
			if (verified?.written !== true) {
				const description =
					"the client authenticates by private_key_jwt under a key written in its record alone";
				return { kind: "error", error: "unauthorized_client", description };
			}
			if (binding === undefined) {
				const description = "a DPoP proof by the client's key is required";
				return { kind: "error", error: "invalid_request", description };
			}
			if (binding.member !== dpopMember) {
				const description = "the client's token is bound by DPoP alone";
				return { kind: "error", error: "unauthorized_client", description };
			}
			// The token's `cnf` is the key the client proved itself with, so using it needs that key.
			if (binding.confirmation !== verified.thumbprint) {
				const description =
					"the proof's key is not the key the client's assertion was verified with";
				return { kind: "error", error: "invalid_dpop_proof", description };
			}
			const audiences = clientAllowance.selfAudiences(client);
			const asked = target([], (a) => audiences.includes(a));
			if (asked.kind === "error") return asked;
			const allowed = clientAllowance.allowedSelfIssuance(
				client,
				param("scope"),
				asked.audience,
				issuer,
			);
			if (allowed.kind === "error") return allowed;
			const { scope, audience } = allowed;
			// A `resource` asked that no rule read is never passed over for the one entry's audience.
			const resource = param("resource");
			if (asked.audience.length === 0 && resource !== undefined && audience[0] !== resource) {
				const description = "the resource asked is not the audience given";
				return { kind: "error", error: "invalid_target", description };
			}
			// Nothing is used up before issuing, but the count, so `issue` alone asks the policies.
			const access = { subject: client.id, subjectKind: "client" as const, issuedTo: client.id };
			const { lifetimeSeconds } = limits;
			const issued = await issue({ access: { ...access, audience, scope } }, { lifetimeSeconds });
			if (issued.kind === "refused") return issued;
			const { token, tokenType, expiresIn } = issued.access;
			return {
				kind: "issued",
				body: {
					access_token: token,
					token_type: tokenType,
					expires_in: expiresIn,
					scope: scope.join(" "),
				},
			};
		},
	};
}
