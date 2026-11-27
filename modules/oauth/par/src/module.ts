import { requestSources } from "@mod/authorize";
import { clientAssertion } from "@mod/client-assertion";
import { clients } from "@mod/clients";
import { routes, use } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { senderBinding } from "@mod/sender-binding";
import { pushedRequests } from "./contract.ts";
import { parPath, pushedSource, pushing } from "./push/push.ts";
import { type Settings, section } from "./section.ts";

type Context = BuildContext<Settings>;

// Holds nothing of its own: a pushed request is in its store.
export default defineModule(
	{
		name: "par",
		section,
		replicaSafe: true,
		takes: [clients, clientAssertion, senderBinding, issuer, pushedRequests],
	},
	(m) => [
		m
			.contribute(requestSources)
			.by(async (c: Context) =>
				pushedSource(await c.get(pushedRequests), c.section["pushed-only"]),
			),
		m.contribute(metadata).by((c: Context) => ({
			name: "require_pushed_authorization_requests",
			value: c.section["pushed-only"],
		})),
		m.contribute(metadata).by(async (c) => ({
			name: "pushed_authorization_request_endpoint",
			value: new URL(parPath, (await c.get(issuer)).endpointOrigin).href,
		})),
		m.contribute(routes).by(async (c: Context) => ({
			method: "POST",
			path: parPath,
			uses: [
				use(requestsPerSource, {
					name: "par",
					window: { limit: c.section.requests, ms: c.section.window * 1000 },
				}),
			],
			takes: ["form"],
			crossSite:
				"A client's server pushes it, authenticated by its own credential; it reads no cookie.",
			handle: pushing({
				clients: await c.get(clients),
				assertion: await c.get(clientAssertion),
				bindings: await c.get(senderBinding),
				pushed: await c.get(pushedRequests),
				issuer: (await c.get(issuer)).url,
				maxLifetimeS: c.section["jar-max-lifetime"],
				skewS: c.section["clock-skew"],
				now: c.clock.now,
				token: () => Buffer.from(c.random.bytes(32)).toString("base64url"),
			}),
		})),
	],
);
