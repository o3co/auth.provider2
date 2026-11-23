import { site } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { issuer, type MetadataItem, metadata } from "./contract.ts";
import { section } from "./section.ts";

/**
 * Never read: the kernel builds every provider at boot, so providing this runs the item check
 * whether or not any module collects the items. Kept apart from `issuer`, which contributors may
 * need while built.
 */
const itemsChecked = contract<readonly MetadataItem[]>("issuer.items");

export default defineModule(
	{
		name: "issuer",
		replicaSafe: true,
		section,
		// Tokens and the discovery document would name a plain-http issuer, open to being changed.
		refusedInProduction: (s) =>
			s.url.startsWith("http:")
				? [
						{
							key: "url",
							reason:
								"is plain http, which a production deployment does not take; set kernel.environment = development to try one",
						},
					]
				: [],
		takes: [site, metadata],
	},
	(m) => [
		m.provide(issuer).by(async (c) => {
			const url = c.section.url;
			const endpointOrigin = (await c.get(site)).origin;
			// The endpoints are named on the configured public origin alone, never on a request's.
			if (endpointOrigin === undefined) {
				return c.refuse(
					"http.public-origin",
					"issuer names the endpoints on http.public-origin: write the origin the Front is reached at",
				);
			}
			// Plain http only beside a plain-http public origin, which http takes only with
			// insecure-origin: nothing else says the deployment accepted it.
			if (url.startsWith("http:") && !endpointOrigin.startsWith("http:")) {
				return c.refuse(
					"issuer.url",
					"a plain-http issuer needs a plain-http public origin, accepted by http.insecure-origin",
				);
			}
			return Object.freeze({ url, endpointOrigin });
		}),
		m.provide(itemsChecked).by(async (c) => {
			const contributed = await c.collect(metadata);
			if (contributed.some((item) => item.name === "issuer")) {
				return c.refuse(
					`${metadata.label}:issuer`,
					"the issuer item is the URL, never a contribution",
				);
			}
			return contributed;
		}),
	],
);
