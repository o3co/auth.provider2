import { type Clients, clients } from "@mod/clients";
import { routes, use } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { accessTokens } from "@mod/tokens";
import { revocableKinds } from "./contract.ts";
import { revocationIn, revocationTakes } from "./revocation.ts";
import { section } from "./section.ts";

const revokePath = "/oauth/revoke";
/** A public client's page may revoke its token (RFC 7009 §2.1), and read the challenge and the wait. */
const cors = {
	headers: ["authorization", "content-type"],
	exposes: ["www-authenticate", "retry-after"],
};

const takes = [...revocationTakes, issuer, revocableKinds, clients, accessTokens];

export default defineModule(
	{ name: "token-revocation", replicaSafe: true, section, takes },
	(m) => [
		m.contribute(routes).by(async (c) => {
			const contributed = await c.collect(revocableKinds);
			if (contributed.some((kind) => kind.hint === "access_token")) {
				return c.refuse("token-revocation", "token-revocation owns access token revocation");
			}
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return {
				method: "POST",
				path: revokePath,
				uses: [use(requestsPerSource, { name: "token-revocation", window })],
				crossSite:
					"It reads no cookie: revoking needs the token itself, which a public client may revoke for itself (RFC 7009).",
				cors,
				...(await revocationIn(c, contributed)),
			};
		}),
		// Published only where some token can be revoked, though the route answers either way.
		m.contribute(metadata).by(async (c) => {
			const location = new URL(revokePath, (await c.get(issuer)).endpointOrigin).href;
			return { name: "revocation_endpoint", value: (await revocableIn(c)) ? location : undefined };
		}),
		// RFC 8414 §2: left out, this would read as client_secret_basic alone. A public client may revoke
		// its own tokens (RFC 7009 §2.1).
		m.contribute(metadata).by(async (c) => ({
			name: "revocation_endpoint_auth_methods_supported",
			value: (await revocableIn(c)) ? (await c.get(clients)).methods() : undefined,
		})),
		m.contribute(metadata).by(async (c) => ({
			name: "revocation_endpoint_auth_signing_alg_values_supported",
			value: (await revocableIn(c)) ? signedBy(await c.get(clients)) : undefined,
		})),
	],
);

/** Whether some token can be revoked here. */
const revocableIn = async (c: BuildContext<unknown>) =>
	(await c.get(accessTokens)).revocable() || (await c.collect(revocableKinds)).length > 0;

/** The algorithms signed client credentials may use; none where no method signs. */
const signedBy = (registry: Clients) => {
	const algorithms = registry.signingAlgorithms();
	return algorithms.length > 0 ? algorithms : undefined;
};
