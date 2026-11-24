import type { Algorithm, ExternalJwt } from "@mod/external-jwt";
import { Unavailable } from "@mod/kernel";
import { said } from "./check.ts";
import type { ClientAssertion } from "./contract.ts";
import { clientKeys, keysOf } from "./keys/keys.ts";
import { verifiedOf } from "./proof.ts";

/** `verifiedOf`, and `verifySignedBy` over the client's keys, under the operator's section. */
export function signedBy(p: {
	readonly jwt: ExternalJwt;
	readonly algorithms: readonly Algorithm[];
	readonly skewMs: number;
	readonly maxLifetimeMs: number;
}): ClientAssertion {
	return {
		verifiedOf,
		verifySignedBy: async (client, jwt, typ) => {
			const { algorithms, skewMs, maxLifetimeMs } = p;
			const verifier = p.jwt.verifierOf(keysOf(client.section(clientKeys)), {
				algorithms,
				skewMs,
				maxLifetimeMs,
				typ,
			});
			const verified = await verifier.verify(jwt);
			if (verified.kind === "unavailable") throw new Unavailable("client keys");
			return verified.kind === "valid"
				? { kind: "signed", claims: verified.claims }
				: { kind: "refused", reason: said[verified.reason] };
		},
	};
}
