import type { Algorithm, ExternalJwt } from "@mod/external-jwt";
import { type Log, Unavailable } from "@mod/kernel";
import { said, told } from "./check.ts";
import type { ClientAssertion } from "./contract.ts";
import { keysFor } from "./keys/keys.ts";
import { verifiedOf } from "./proof.ts";

/**
 * `verifiedOf`, and `verifySignedBy` over the client's keys, under the operator's section: a refusal
 * logged for the operator in `said`'s words, by client and `typ`, and answered in `told`'s.
 */
export function signedBy(p: {
	readonly jwt: ExternalJwt;
	readonly algorithms: readonly Algorithm[];
	readonly skewMs: number;
	readonly maxLifetimeMs: number;
	readonly log: Log;
}): ClientAssertion {
	return {
		verifiedOf,
		verifySignedBy: async (client, jwt, typ) => {
			const { algorithms, skewMs, maxLifetimeMs } = p;
			const verifier = p.jwt.verifierOf(keysFor(client), {
				algorithms,
				skewMs,
				maxLifetimeMs,
				typ,
			});
			const verified = await verifier.verify(jwt);
			if (verified.kind === "unavailable") throw new Unavailable("client keys");
			if (verified.kind === "valid") return { kind: "signed", claims: verified.claims };
			// The detail the sender is not told (which key, how many fit) is the operator's alone.
			p.log.warn("client-assertion.jwt_refused", {
				client: client.id,
				typ,
				reason: said[verified.reason],
			});
			return { kind: "refused", reason: told[verified.reason] };
		},
	};
}
