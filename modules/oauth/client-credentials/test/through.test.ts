import { generateKeyPairSync, type KeyObject, randomUUID } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientAssertionModule from "@mod/client-assertion/module";
import { clientKeysFor } from "@mod/client-assertion/testing";
import clientAssertionStore from "@mod/client-assertion-store/module";
import { clientSources } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import dpopModule from "@mod/dpop/module";
import { dpopConfig } from "@mod/dpop/testing";
import dpopStore from "@mod/dpop-store/module";
import externalJwtModule from "@mod/external-jwt/module";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import outboundModule from "@mod/outbound/module";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import { simulatedStore } from "@mod/store/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import tokenEndpointModule from "@mod/token-endpoint/module";
import { accessTokens } from "@mod/tokens";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import { frameStore, stateOwners, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { SignJWT } from "jose";
import { afterEach, expect, it } from "vitest";
import clientCredentialsModule from "../src/module.ts";

const issuer = "https://issuer.example";
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwkOf = (key: KeyObject) => key.export({ format: "jwk" });

/** The log and frames in memory, the log on the composition's clock, each append verified at once. */
const transparencyInMemory = defineModule(
	{ name: "transparency-in-memory", replicaSafe: true, takes: [] },
	(m) => [
		m.provide(frameStore).by(() => memoryFrames(["state"]).frames),
		m.provide(transparencyLog).by((c) => {
			const book = logBook(c.clock.now);
			book.judgeOnAppend({ verdict: "verified", outcome: "took" });
			return book.as("w1");
		}),
		m.contribute(stateOwners).by(() => ({
			name: "every-field",
			holds: ["keyGeneration", "keys", "approvals", "families", "consumed"],
			parts: ["state"],
			records: () => [{ part: "state", name: "state" }],
			read: () => ({}),
			write: () => [undefined],
		})),
	],
);
/** The client, as the registry's signed version 3 names it: its one key, `ec`, and `read` at the API. */
const registry = defineModule({ name: "registry", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(clientSources).by(() => ({
		signed: true,
		find: async (id) =>
			id === "svc"
				? {
						id,
						kind: "confidential",
						method: "private_key_jwt",
						sections: {
							...allowancesFor({
								grants: ["client_credentials"],
								self: [{ audience: "https://api.example", scopes: ["read"] }],
							}),
							...clientKeysFor([{ ...jwkOf(ec.publicKey), kid: "ec" }]),
						},
						version: 3,
					}
				: undefined,
	})),
]);

let stop = async () => {};
afterEach(() => stop());

async function serve() {
	const app = await assemble({
		modules: [
			http,
			testServer(),
			keysModule,
			testHolder(),
			tokensModule,
			issuerModule,
			senderBindingModule,
			dpopModule,
			dpopStore,
			simulatedStore().module,
			clientsModule,
			secretHashModule,
			clientAllowanceModule,
			outboundModule,
			tlsOptionsForTests,
			externalJwtModule,
			clientAssertionModule,
			clientAssertionStore,
			rateLimitStandIn,
			auditStandIn().module,
			transparencyModule,
			transparencyInMemory,
			promisesModule,
			tokenEndpointModule,
			clientCredentialsModule,
			registry,
		],
		config: {
			...kernelConfig(),
			outbound: {},
			...httpConfig({ "public-origin": issuer }),
			...keysConfig(),
			...issuerConfig({ url: issuer }),
			...tokensConfig(),
			...dpopConfig(),
			...clientsConfig([]),
		},
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const at = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const now = () => Math.floor(Date.now() / 1000);
	const assertion = () =>
		new SignJWT({ iss: "svc", sub: "svc", aud: issuer, jti: randomUUID(), exp: now() + 60 })
			.setProtectedHeader({ alg: "ES256", kid: "ec" })
			.sign(ec.privateKey);
	const proof = (key: KeyObject, publicKey: KeyObject) =>
		new SignJWT({ jti: randomUUID(), htm: "POST", htu: `${issuer}/oauth/token`, iat: now() })
			.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: jwkOf(publicKey) })
			.sign(key);
	/** A client credentials request for `read`, its client proved by `ec`, its token bound by DPoP to `pair`'s key, or by none. */
	const post = async (pair?: { privateKey: KeyObject; publicKey: KeyObject }) => {
		const res = await fetch(at, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				...(pair ? { dpop: await proof(pair.privateKey, pair.publicKey) } : {}),
			},
			body: new URLSearchParams({
				grant_type: "client_credentials",
				scope: "read",
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: await assertion(),
			}),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	return { post, tokens: app.get(accessTokens), judged: app.get(promises).judgment() };
}

it("issues a DPoP-bound token only by the key its assertion was verified with, of the registry's version", async () => {
	const { post, tokens } = await serve();
	const same = await post(ec);
	expect(same).toMatchObject({ status: 200, body: { token_type: "DPoP", scope: "read" } });
	// Its lifetime is the token's own, five minutes; `expires_in` counts what is left once answered.
	const [, claims = ""] = String(same.body.access_token).split(".");
	const { iat, exp } = JSON.parse(Buffer.from(claims, "base64url").toString()) as {
		iat: number;
		exp: number;
	};
	expect(exp - iat).toBe(300);
	expect(same.body.expires_in).toBeGreaterThan(0);
	expect(same.body.expires_in).toBeLessThanOrEqual(exp - iat);
	const checked = await tokens.verifyAccess(String(same.body.access_token));
	expect(checked).toMatchObject({
		kind: "valid",
		grant: { subject: "svc", subjectKind: "client", audience: ["https://api.example"] },
	});
	expect(await post(other)).toEqual({
		status: 400,
		body: {
			error: "invalid_dpop_proof",
			error_description: "the proof's key is not the key the client's assertion was verified with",
		},
	});
});

it("refuses a request whose token would be bound by no DPoP proof", async () => {
	const { post } = await serve();
	expect(await post()).toEqual({
		status: 400,
		body: {
			error: "invalid_request",
			error_description: "a DPoP proof by the client's key is required",
		},
	});
});

it("composed, breaks the promise that no client subject token is issued, naming itself", async () => {
	const { judged } = await serve();
	expect(judged.find((j) => j.promise === promiseNames.noClientSubjectToken)).toMatchObject({
		held: false,
		breaking: [
			{
				by: "token-endpoint",
				reason: expect.stringContaining("client_credentials (client-credentials)"),
			},
		],
	});
});
