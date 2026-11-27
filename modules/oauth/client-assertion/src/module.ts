import { authMethods, clients, metadataSections } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { pkcs1v15Deprecated } from "@mod/keys";
import { stances } from "@mod/promises";
import { clientAssertion } from "./contract.ts";
import { clientKeys, clientKeysIn, keysStance, keysTakes, unreadKeys } from "./keys/keys.ts";
import { assertionMethod, methodEndpointIn, methodIn, methodTakes } from "./method/method.ts";
import { section } from "./section.ts";
import { signedBy } from "./signed.ts";

/** What the module takes: `clientKeysIn`'s, the method's, `external-jwt` for `clientAssertion` too, and the clients its start warns of. */
const takes = [...new Set([...keysTakes, ...methodTakes, externalJwt, clients])];

const pkcs1v15: ReadonlySet<string> = new Set(["RS256", "RS384", "RS512"]);

export default defineModule(
	{ name: "client-assertion", replicaSafe: true, section, takes },
	(m) => [
		m.contribute(metadataSections).by((c) => clientKeysIn(c)),
		m.contribute(stances).by(async (c) => keysStance((await c.get(clients)).registered())),
		m.provide(clientAssertion).by(async (c) => {
			// The operator's choice, yet said at every start, in keys' words: PKCS#1 v1.5's three alike.
			const pkcs1 = c.section.algorithms.filter((alg) => pkcs1v15.has(alg));
			if (pkcs1.length > 0) {
				c.log.warn("client-assertion.pkcs1v15_deprecated", {
					algorithms: pkcs1.join(" "),
					reason: pkcs1v15Deprecated,
				});
			}
			return signedBy({
				jwt: await c.get(externalJwt),
				algorithms: c.section.algorithms,
				skewMs: c.section["clock-skew"] * 1000,
				maxLifetimeMs: c.section["max-lifetime"] * 1000,
				log: c.log,
			});
		}),
		m.contribute(authMethods).by(async (c) => {
			const tokenEndpoint = await methodEndpointIn(c);
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
			return assertionMethod(await methodIn(c, tokenEndpoint));
		}),
	],
);
