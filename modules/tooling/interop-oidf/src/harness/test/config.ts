/**
 * What the harness gives the suite for a run: its clients, registered in the scene's signed registry,
 * and the plan's configuration (the server, both clients, the resource, the browser). Each client's
 * sections are their modules' `./testing`, so its files are tests'.
 */
import { generateKeyPairSync } from "node:crypto";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientKeysFor } from "@mod/client-assertion/testing";
import { redirectsFor } from "@mod/redirect-uris/testing";
import { senderBindingFor } from "@mod/sender-binding/testing";
import type { RegistryClient } from "../../scene/test/scene.ts";
import { suiteOrigin } from "../../suite/suite.ts";

/** Run A's plan and the variant it is run under, as the expected results name it. */
export const planA = "fapi2-message-signing-final-test-plan";
export const variantA: Readonly<Record<string, string>> = Object.freeze({
	openid: "openid_connect",
	client_auth_type: "private_key_jwt",
	fapi_request_method: "signed_non_repudiation",
	sender_constrain: "dpop",
	fapi_profile: "plain_fapi",
	fapi_response_mode: "plain_response",
});

/** The scopes each client asks: more than one, as the suite asks of its configuration (#8), and each allowed. */
export const scopes = ["openid", "email"] as const;

/** A client of the suite's: its id, its private key set for the suite, and its record for the registry. */
export interface SuiteClient {
	readonly id: string;
	readonly jwks: { readonly keys: readonly Readonly<Record<string, unknown>>[] };
	readonly registered: RegistryClient;
}

/** The suite's callback for a plan's alias, and the same with a query the suite adds to tell them apart. */
export const callbacksOf = (alias: string) => {
	const callback = `${suiteOrigin}/test/a/${alias}/callback`;
	return [callback, `${callback}?dummy1=lorem&dummy2=ipsum`] as const;
};

/** A confidential client signing by one ES256 key of its own (a `kid`), at the suite's callbacks, bound to a DPoP key. */
export function clientOf(id: string, alias: string): SuiteClient {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const named = { kid: `${id}-key`, alg: "ES256", use: "sig" };
	const pub = { ...pair.publicKey.export({ format: "jwk" }), ...named };
	const priv = { ...pair.privateKey.export({ format: "jwk" }), ...named };
	return {
		id,
		jwks: { keys: [priv] },
		registered: {
			id,
			kind: "confidential",
			method: "private_key_jwt",
			sections: {
				...clientKeysFor([pub]),
				...redirectsFor([...callbacksOf(alias)]),
				...allowancesFor({ grants: ["authorization_code", "refresh_token"], scopes: [...scopes] }),
				...senderBindingFor({ required: true }),
			},
		},
	};
}

/** Where a run is reached: the plan's alias, the issuer, the screen's origin and the resource's URL. */
export interface Reached {
	readonly alias: string;
	readonly issuer: string;
	readonly screen: string;
	readonly resource: string;
}

/**
 * The browser, from the screen's authorization page: approve there (or, for a module told so, deny),
 * and where the screen sent it on to its page of a refusal, fill the review's placeholder with that
 * page. The suite runs the tasks of the one entry matching the URL it opens, in order, each optional
 * one skipped where the page's URL is another; each command is optional too.
 */
export function browserOf(screen: string, choice: "approve" | "deny" = "approve") {
	return [
		{
			match: `${screen}/authorize*`,
			tasks: [
				{
					task: choice === "approve" ? "Approve" : "Deny",
					match: `${screen}/authorize*`,
					optional: true,
					commands: [["click", "id", choice, "optional"]],
				},
				{
					task: "Show the refusal",
					match: `${screen}/refused*`,
					optional: true,
					commands: [["wait", "id", "refused", 10, "refused", "update-image-placeholder-optional"]],
				},
			],
		},
	];
}

/** The modules the browser denies, by their names: the user rejecting the authentication (#3). */
export const denied = ["fapi2-security-profile-final-user-rejects-authentication"] as const;

/** The plan's configuration: the server by its discovery, both clients, the resource, the browser and its overrides. */
export function planConfig(at: Reached, clients: readonly [SuiteClient, SuiteClient]) {
	const client = (c: SuiteClient) => ({
		client_id: c.id,
		scope: scopes.join(" "),
		jwks: c.jwks,
		dpop_signing_alg: "ES256",
	});
	return {
		alias: at.alias,
		description: "nextgen, run A",
		server: { discoveryUrl: `${at.issuer}/.well-known/openid-configuration` },
		client: client(clients[0]),
		client2: client(clients[1]),
		resource: { resourceUrl: at.resource },
		browser: browserOf(at.screen),
		override: Object.fromEntries(
			denied.map((name) => [name, { browser: browserOf(at.screen, "deny") }]),
		),
	};
}
