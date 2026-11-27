import { acr, amrSources } from "@mod/acr";
import { statementItems } from "@mod/approvals";
import { documentCopies } from "@mod/client-documents";
import { metadataSections } from "@mod/clients";
import { routes } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { promiseNames, stances } from "@mod/promises";
import { redirects, redirectsCopy } from "@mod/redirect-uris";
import { authorizationRequests, requestSources, signUpOffers, withoutPasskey } from "./contract.ts";
import { delegationSecondsIn, delegationTakes } from "./delegation/delegation.ts";
import { finishRoute, finishTakes, passkeyAmr } from "./finish/finish.ts";
import { requestsIn, requestsTakes } from "./request/request.ts";
import { type Settings, section } from "./section.ts";
import {
	byValue,
	filledItems,
	issuerMetadata,
	onlyOf,
	requestObjectAlgorithmsIn,
	startRouteIn,
	startTakes,
	takenOf,
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
			...new Set([
				...startTakes,
				...requestsTakes,
				withoutPasskey,
				signUpOffers,
				statementItems,
				acr,
				...delegationTakes,
				...finishTakes,
			]),
		],
	},
	(m) => [
		m.provide(authorizationRequests).by((c: Context) => requestsIn(c)),
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
		// The JAR by value is supported where the start takes it.
		m.contribute(metadata).by(async (c: Context) => ({
			...issuerMetadata.requestParameter,
			value: takenOf(await c.collect(requestSources)).includes(byValue),
		})),
		// Published either way: OpenID Connect Discovery's default for it is true.
		m.contribute(metadata).by(async (c: Context) => ({
			...issuerMetadata.requestUriParameter,
			value: takenOf(await c.collect(requestSources)).some((s) => s.readsRequestUri === true),
		})),
		m.contribute(metadata).by(() => issuerMetadata.issParameter),
		m.contribute(metadata).by((c: Context) => requestObjectAlgorithmsIn(c)),
		m.contribute(routes).by(async (c: Context) => {
			const passkeyless = await c.collect(withoutPasskey);
			if (passkeyless.length > 1)
				return c.refuse(
					"authorize",
					"more than one answer to a person with no passkey is contributed",
				);
			if (onlyOf(await c.collect(requestSources)).length > 1)
				return c.refuse("authorize", "more than one request source says it is the only one");
			const offers = await c.collect(signUpOffers);
			if (offers.length > 1) return c.refuse("authorize", "more than one sign-up is offered");
			// A sign-up offered with no answer to a person with no passkey would never be allowed.
			if (offers.length === 1 && passkeyless.length === 0)
				return c.refuse(
					"authorize",
					"a sign-up is offered, but no answer to a person with no passkey",
				);
			// An item every T carries that no module fills would refuse every start: dpop_jkt's bridge left out.
			const missing = unfilled(await c.collect(statementItems));
			if (missing.length > 0)
				return c.refuse("authorize", `no module fills the authorization's ${missing.join(", ")}`);
			return startRouteIn(c, { withoutPasskey: passkeyless[0], signUp: offers.length === 1 });
		}),
		m.contribute(routes).by(async (c: Context) =>
			finishRoute(c, {
				issuer: (await c.get(issuer)).url,
				// The delegation's length is refresh's (O27): the session ends with its family.
				delegationS: await delegationSecondsIn(c),
				window: { limit: c.section.requests, ms: c.section.window * 1000 },
				// The one acr a passkey's login meets, as `acr`'s table fixes it.
				acr: (await c.get(acr)).current(passkeyAmr),
			}),
		),
	],
);
