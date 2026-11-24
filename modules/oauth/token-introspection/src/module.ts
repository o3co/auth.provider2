import { type Clients, clients } from "@mod/clients";
import { routes, use } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { requestsPerSource } from "@mod/rate-limit";
import { introspectionIn, introspectionTakes } from "./introspection.ts";
import { section } from "./section.ts";

const introspectPath = "/oauth/introspect";

/** Why answering introspection breaks both promises a compromised Front must not break (RFC 7662 answers are unsigned and unbound). */
const reason =
	"an introspection answer is bound to neither the token asked about nor the request: a resource server that trusts it trusts the Front that relays it, which can answer a token the Core never issued as active, for any subject and with its own key as the binding";

const takes = [...introspectionTakes, issuer, clients];

export default defineModule(
	{ name: "token-introspection", replicaSafe: true, section, takes },
	(m) => [
		m.contribute(routes).by(async (c) => {
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return {
				method: "POST",
				path: introspectPath,
				uses: [use(requestsPerSource, { name: "token-introspection", window })],
				crossSite: "A resource server's call, authenticated as a client; it reads no cookie.",
				...(await introspectionIn(c)),
			};
		}),
		m.contribute(metadata).by(async (c) => ({
			name: "introspection_endpoint",
			value: new URL(introspectPath, (await c.get(issuer)).endpointOrigin).href,
		})),
		// RFC 8414 §2: left out, this would read as client_secret_basic alone. A public client never
		// introspects (RFC 7662 §2.1).
		m.contribute(metadata).by(async (c) => ({
			name: "introspection_endpoint_auth_methods_supported",
			value: (await c.get(clients)).methods().filter((method) => method !== "none"),
		})),
		m.contribute(metadata).by(async (c) => ({
			name: "introspection_endpoint_auth_signing_alg_values_supported",
			value: signedBy(await c.get(clients)),
		})),
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: false,
			by: "token-introspection",
			reason,
		})),
		m.contribute(stances).by(() => ({
			promise: promiseNames.clientToken,
			holds: false,
			by: "token-introspection",
			reason,
		})),
	],
);

/** The algorithms signed client credentials may use; none where no method signs. */
const signedBy = (registry: Clients) => {
	const algorithms = registry.signingAlgorithms();
	return algorithms.length > 0 ? algorithms : undefined;
};
