import type { Client, Section } from "@mod/clients";
import { type Algorithm, boundAlgorithm, type KeySource } from "@mod/external-jwt";
import type { BuildContext } from "@mod/kernel";
import { publicJwk, verifiesUnder } from "@mod/keys";
import { destinationRefusal, type OutboundRefusals, outboundRefusals } from "@mod/outbound-policy";
import { promiseNames, type Stance } from "@mod/promises";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export type Jwk = Readonly<Record<string, unknown>>;

/** A public key for verifying signatures, read by `keys`' rules. */
const verifiesSignatures = (jwk: Jwk) => publicJwk(jwk) !== undefined && verifiesUnder(jwk);

/** The client's keys for its assertions: public keys written into its record, or a key set's URL. */
export interface ClientKeys {
	readonly keys: readonly Jwk[];
	readonly "jwks-uri"?: string | undefined;
	/** Also takes the token endpoint's URL, or a list, as an assertion's audience. */
	readonly "accept-loose-audience": boolean;
}

export const clientKeys: Section<ClientKeys> = {
	name: "client-assertion",
	schema: z
		.strictObject({
			keys: z
				.array(
					z
						.record(z.string(), z.unknown())
						.refine(verifiesSignatures, "a public RSA, EC or Ed25519 key for verifying signatures"),
				)
				.prefault([])
				.describe(
					"The client's public keys for its assertions, as JWKs: RSA, EC or OKP Ed25519 (never Ed448), with no private member; never beside `jwks-uri`. A registered client's key that none of `client-assertion.algorithms` reads is warned of at every start, by its place; deprecated, a later release refuses boot for it.",
				),
			"jwks-uri": urlSetting({ schemes: ["https", "http"] })
				.optional()
				.describe(
					"Where the client publishes its key set, an https URL (http only where `outbound` allows plain http); never beside written `keys`. A registered client's one that `outbound` refuses refuses boot.",
				),
			"accept-loose-audience": z
				.boolean()
				.prefault(false)
				.describe(
					"A registered client's alone (a source's client takes none): also takes, from this client, an assertion whose `aud` is the token endpoint's URL or a list holding the issuer's or the token endpoint's URL, as 0.18.5 did; each is logged. While set, an assertion the client made for another authorization server that names this one's token endpoint can be used here. For a client whose library names the token endpoint; a registered client that sets it is warned of at every start.",
				),
		})
		.refine((s) => s.keys.length === 0 || s["jwks-uri"] === undefined, {
			message: "keys written in, or a jwks-uri, not both",
			path: ["jwks-uri"],
		}),
};

/** Where the client's keys come from: its key set's URL, fetched from that URL's host alone, or its written keys. */
export function keysOf(section: ClientKeys): KeySource {
	const uri = section["jwks-uri"];
	return uri === undefined
		? { inline: section.keys }
		: { jwks: { url: uri, hosts: [new URL(uri).hostname] } };
}

/**
 * The client's keys as an assertion or a JWT of its is checked against: a source's client takes its
 * written keys alone, as a source never names a key set to fetch (R8, §3.11): one naming a `jwks-uri`
 * has no key, and nothing is fetched for it.
 */
export function keysFor(client: Pick<Client, "registered" | "section">): KeySource {
	const section = client.section(clientKeys);
	return !client.registered && section["jwks-uri"] !== undefined ? { inline: [] } : keysOf(section);
}

/** The places (`keys.<n>`) of the written keys that none of the algorithms taken reads. */
export function unreadKeys(section: ClientKeys, algorithms: readonly Algorithm[]): string[] {
	return section.keys.flatMap((jwk, i) =>
		boundAlgorithm(jwk, algorithms) === undefined ? [`keys.${i}`] : [],
	);
}

/** The section with its check at boot: `outbound`'s policy lets a registered client's jwks-uri through. */
export function clientKeysUnder(refusals: OutboundRefusals): Section<ClientKeys> {
	return {
		...clientKeys,
		checkAtBoot: (section) => {
			const source = keysOf(section);
			if (!("jwks" in source)) return undefined;
			return destinationRefusal(
				refusals,
				source.jwks.url,
				{ hosts: source.jwks.hosts },
				"the jwks-uri",
			);
		},
	};
}

/**
 * Where the keys stand on the promise of a client's token (claim 2), by the registered clients'
 * sections: broken by one naming a jwks-uri, whose key set is whoever serves it (or, over plain http,
 * sits on its path), or taking a loose audience, an assertion made for another server taken here;
 * each named by its place and field, never its id. Held otherwise: its keys are written in.
 */
export function keysStance(registered: readonly Pick<Client, "section">[]): Stance {
	// The first client weakening it, either way, in the settings' order.
	for (const [i, client] of registered.entries()) {
		const keys = client.section(clientKeys);
		const field =
			keys["jwks-uri"] !== undefined
				? "jwks-uri"
				: keys["accept-loose-audience"]
					? "accept-loose-audience"
					: undefined;
		if (field === undefined) continue;
		return {
			promise: promiseNames.clientToken,
			holds: false,
			by: "client-assertion",
			setting: `clients.registered.${i}.sections.client-assertion.${field}`,
			reason:
				field === "jwks-uri"
					? "a key set fetched is whoever serves it, or sits on its path"
					: "an assertion made for another server is taken here",
		};
	}
	return { promise: promiseNames.clientToken, holds: true, by: "client-assertion" };
}

/** Whether a client's assertion is also taken for a loose audience: a registered client's choice alone (§0.2). */
export const looseFor = (client: Pick<Client, "registered" | "section">) =>
	client.registered && client.section(clientKeys)["accept-loose-audience"];

/** What `clientKeysIn` takes from the build context. */
export const keysTakes = [outboundRefusals] as const;

/** The section as the composition gives it, with `outbound`'s refusals read from it. */
export async function clientKeysIn(
	c: Pick<BuildContext<unknown>, "get">,
): Promise<Section<ClientKeys>> {
	return clientKeysUnder(await c.get(outboundRefusals));
}
