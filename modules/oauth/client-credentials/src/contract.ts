import { clientAllowance } from "@mod/client-allowance";
import type { ClientAssertion } from "@mod/client-assertion";
import type { Grant } from "@mod/grants";

/** The grant type it serves (RFC 6749 §4.4). */
export const clientCredentialsGrantType = "client_credentials";

/** The binding member a DPoP proof's key confirms a token by: its JWK SHA-256 thumbprint (RFC 9449 §6). */
const dpopMember = "jkt";

/**
 * The client credentials grant at `issuer`: a confidential client takes a token for itself, within
 * its allowance, in one bundle on its own flow; a DPoP-bound one only by the key its assertion was
 * verified with (`keys`).
 */
export function clientCredentials(
	issuer: string,
	keys: Pick<ClientAssertion, "verifiedOf">,
): Grant {
	return {
		grantType: clientCredentialsGrantType,
		readsAmbient: "none",
		targets: true,
		handle: async ({ client, param, binding, proof, issue, target }) => {
			if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
			const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuer);
			if (allowed.kind === "error") return allowed;
			const { scope } = allowed;
			const asked = target(allowed.audience, (a) =>
				clientAllowance.allowsAudience(client, a, issuer),
			);
			if (asked.kind === "error") return asked;
			const { audience } = asked;
			// The proof's key is the one the client proved itself with, of the registry version it came
			// from: the token's `cnf`, so using it needs the client's private key.
			const verified = keys.verifiedOf(proof);
			if (binding?.member === dpopMember && binding.confirmation !== verified?.thumbprint) {
				const description =
					"the proof's key is not the key the client's assertion was verified with";
				return { kind: "error", error: "invalid_dpop_proof", description };
			}
			// Nothing is used up before issuing, so `issue` alone asks the policies.
			const access = { subject: client.id, subjectKind: "client" as const, issuedTo: client.id };
			const issued = await issue({ access: { ...access, audience, scope } });
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
