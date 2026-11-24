import { generateKeyPairSync, type KeyObject } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import type { AccessTokenSigning } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import type { AccessGrant, IssueLimits, Tokens } from "../src/contract.ts";
import tokensModule from "../src/module.ts";

/** The authority's signing key every test composition signs with, as kid `k` under EdDSA: one across boots. */
export const signingKey = generateKeyPairSync("ed25519").privateKey;

/** What a test's composition of tokens holds at least: http, keys and its holder, with `signingKey` and those given, issuer, sender-binding and tokens. */
export const composedWith = (held: Readonly<Record<string, KeyObject>> = {}) => [
	http,
	testServer(),
	keysModule,
	testHolder({ k: signingKey, ...held }),
	issuerModule,
	senderBindingModule,
	tokensModule,
];

export const composedModules = composedWith();

/** The http section, on the public origin issuer names the endpoints on. */
export const composedHttp = (origin = "https://issuer.example") =>
	httpConfig({ "public-origin": origin });

/** The keys section, `signingKey` signing the authority's ring. */
export const composedKeys = () =>
	keysConfig({ authority: { signing: { kid: "k", alg: "EdDSA" } } });

/** Their sections, tokens' own left to each test. */
export const composedConfig = () => ({
	...kernelConfig(),
	...composedHttp(),
	...composedKeys(),
	...issuerConfig(),
});

/** An access token signed through accessTokenSigning with these claims, as a test writes them. */
export async function signAccess(signer: AccessTokenSigning, claims: object): Promise<string> {
	const bytes = new TextEncoder().encode(JSON.stringify(claims));
	const signed = await signer.sign(signer.prepare(), bytes);
	if (signed.kind !== "signed") throw new Error("withdrawn");
	return signed.jws;
}

/** Issues through `issue`, which nothing in the tests using it refuses, and answers what it issued. */
export async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}
