import { authMethods, clients, metadataSections } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { site } from "@mod/http";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { rs256Deprecated } from "@mod/keys";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { clientAssertion } from "./contract.ts";
import { clientKeys, clientKeysIn, keysTakes, unreadKeys } from "./keys/keys.ts";
import { assertionMethod } from "./method.ts";
import { section } from "./section.ts";
import { signedBy } from "./signed.ts";
import { spentAssertions } from "./store.ts";

/** What the module takes: `clientKeysIn`'s, what the method is built over, the site, and the clients its start warns of. */
const takes = [
	...keysTakes,
	tokenEndpointLocation,
	spentAssertions,
	externalJwt,
	issuer,
	site,
	clients,
];

export default defineModule(
	{ name: "client-assertion", replicaSafe: true, section, takes },
	(m) => [
		m.contribute(metadataSections).by((c) => clientKeysIn(c)),
		m.provide(clientAssertion).by(async (c) => {
			// The operator's choice, yet said at every start, in keys' words.
			if (c.section.algorithms.includes("RS256")) {
				c.log.warn("client-assertion.rs256_deprecated", { reason: rs256Deprecated });
			}
			return signedBy({
				jwt: await c.get(externalJwt),
				algorithms: c.section.algorithms,
				skewMs: c.section["clock-skew"] * 1000,
				maxLifetimeMs: c.section["max-lifetime"] * 1000,
			});
		}),
		m.contribute(authMethods).by(async (c) => {
			const { url } = await c.get(tokenEndpointLocation);
			// A public origin is required, as written, though the token endpoint has a location without one.
			if ((await c.get(site)).origin === undefined || url === undefined) {
				return c.refuse("client-assertion", "the token endpoint's location needs a public origin");
			}
			// Told at each start, by client: an assertion such a client made for another authorization
			// server that names this one's token endpoint can be used here; and each written key none of
			// the algorithms taken reads, as no assertion is checked against it.
			const known = c.late(clients);
			c.onStart(() => {
				for (const client of known().registered()) {
					const keys = client.section(clientKeys);
					if (keys["accept-loose-audience"]) {
						c.log.warn("client-assertion.accept_loose_audience", { client: client.id });
					}
					for (const key of unreadKeys(keys, c.section.algorithms)) {
						c.log.warn("client-assertion.key_unread", { client: client.id, key });
					}
				}
			});
			return assertionMethod({
				spent: await c.get(spentAssertions),
				jwt: await c.get(externalJwt),
				issuer: (await c.get(issuer)).url,
				tokenEndpoint: url,
				maxLifetimeMs: c.section["max-lifetime"] * 1000,
				skewMs: c.section["clock-skew"] * 1000,
				algorithms: c.section.algorithms,
				clock: c.clock,
				log: c.log,
			});
		}),
	],
);
