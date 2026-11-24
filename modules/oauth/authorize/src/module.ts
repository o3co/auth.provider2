import { acr, amrSources } from "@mod/acr";
import { approvals, statementItems } from "@mod/approvals";
import { clientAssertion } from "@mod/client-assertion";
import { documentCopies } from "@mod/client-documents";
import { clients, metadataSections } from "@mod/clients";
import { routes } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { redirects, redirectsCopy } from "@mod/redirect-uris";
import { jarReservations, requestSources, withoutPasskey } from "./contract.ts";
import { finishRoute, finishTakes, passkeyAmr } from "./finish/finish.ts";
import { reserving } from "./jar/jar.ts";
import { type Settings, section } from "./section.ts";
import {
	bindingsIn,
	byValue,
	filledItems,
	idTokensIn,
	issuerMetadata,
	startRoute,
	unfilled,
} from "./start/start.ts";

type Context = BuildContext<Settings>;

// Holds nothing of its own: a JAR's reservation is in its store.
export default defineModule(
	{
		name: "authorize",
		section,
		replicaSafe: true,
		takes: [
			clients,
			clientAssertion,
			approvals,
			issuer,
			jarReservations,
			requestSources,
			withoutPasskey,
			statementItems,
			acr,
			...finishTakes,
		],
	},
	(m) => [
		m.contribute(metadataSections).by(() => redirects),
		m.contribute(documentCopies).by(() => redirectsCopy),
		m.contribute(requestSources).by(() => byValue),
		m.contribute(statementItems).by(() => filledItems),
		// The amr a login it finishes carries, which `acr`'s table is checked against.
		m.contribute(amrSources).by(() => ({ name: "authorize.passkey", amr: passkeyAmr })),
		// It takes `approvals`, which asks where its takers stand: it starts a login only on a statement.
		m.contribute(stances).by(() => ({
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "authorize",
		})),
		m.contribute(metadata).by((c: Context) => ({
			name: "authorization_endpoint",
			value: c.section["screen-url"],
		})),
		m.contribute(metadata).by(() => issuerMetadata.responseTypes),
		m.contribute(metadata).by(() => issuerMetadata.responseModes),
		m.contribute(metadata).by(() => issuerMetadata.challengeMethods),
		m.contribute(metadata).by(() => issuerMetadata.signedRequest),
		m.contribute(metadata).by(() => issuerMetadata.requestParameter),
		m.contribute(metadata).by(() => issuerMetadata.issParameter),
		m.contribute(routes).by(async (c: Context) => {
			const passkeyless = await c.collect(withoutPasskey);
			if (passkeyless.length > 1)
				return c.refuse(
					"authorize",
					"more than one answer to a person with no passkey is contributed",
				);
			// An item every T carries that no module fills would refuse every start: dpop_jkt's bridge left out.
			const missing = unfilled(await c.collect(statementItems));
			if (missing.length > 0)
				return c.refuse("authorize", `no module fills the authorization's ${missing.join(", ")}`);
			const window = { limit: c.section.requests, ms: c.section.window * 1000 };
			return startRoute(
				{
					clients: await c.get(clients),
					jar: {
						sources: await c.collect(requestSources),
						assertion: await c.get(clientAssertion),
						issuer: (await c.get(issuer)).url,
						maxLifetimeS: c.section["jar-max-lifetime"],
						now: c.clock.now,
					},
					reserve: reserving({
						reservations: await c.get(jarReservations),
						skewS: c.section["clock-skew"],
						now: c.clock.now,
						token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
					}),
					approvals: await c.get(approvals),
					withoutPasskey: passkeyless[0],
					bindings: await bindingsIn(c),
					idTokens: await idTokensIn(c),
				},
				window,
			);
		}),
		m.contribute(routes).by(async (c: Context) =>
			finishRoute(c, {
				issuer: (await c.get(issuer)).url,
				delegationS: c.section["delegation-lifetime"],
				window: { limit: c.section.requests, ms: c.section.window * 1000 },
				// The one acr a passkey's login meets, as `acr`'s table fixes it.
				acr: (await c.get(acr)).current(passkeyAmr),
			}),
		),
	],
);
