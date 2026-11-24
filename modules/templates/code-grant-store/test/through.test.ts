import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientSecret, clientsConfig, confidentialClient } from "@mod/clients/testing";
import { codes } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import dpopModule from "@mod/dpop/module";
import { dpopConfig } from "@mod/dpop/testing";
import dpopStore from "@mod/dpop-store/module";
import { sessionIssuances } from "@mod/grants";
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
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import senderBindingModule from "@mod/sender-binding/module";
import { sessions } from "@mod/session";
import { openedOf } from "@mod/session/testing";
import sessionLifecycle from "@mod/session-lifecycle/module";
import { sessionLifecycleConfig } from "@mod/session-lifecycle/testing";
import sessionParticipants from "@mod/session-participants/module";
import sessionStore from "@mod/session-store/module";
import { simulatedStore } from "@mod/store/testing";
import revocationModule from "@mod/subject-revocation/module";
import revocationStore from "@mod/subject-revocation-store/module";
import tokenEndpoint from "@mod/token-endpoint/module";
import { accessTokens } from "@mod/tokens";
import tokensModule from "@mod/tokens/module";
import { tokensConfig } from "@mod/tokens/testing";
import tokensStore from "@mod/tokens-store/module";
import { frameStore, stateOwners, transparencyLog } from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime();
/** The client's DPoP key, which its authorization asked for ahead. */
const held = generateKeyPairSync("ec", { namedCurve: "P-256" });
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
/** Records each token issued from a session, in place of session-tokens, which is not composed here. */
const recorder = defineModule({ name: "session-recorder", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(sessionIssuances).by(() => ({ issued: async () => {} })),
]);
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");

it("redeems a code bound by DPoP once through code-grant wired to records, and revokes what it gave when it comes again [rfc6749-4.1.2-d] [rfc6749-4.1.2-e] [rfc9449-10-a]", async () => {
	const app = await assemble({
		modules: [
			http,
			testServer(),
			keysModule,
			testHolder(),
			tokensModule,
			tokensStore,
			issuerModule,
			senderBindingModule,
			clientsModule,
			secretHashModule,
			clientAllowanceModule,
			tokenEndpoint,
			rateLimitStandIn,
			auditStandIn().module,
			sessionLifecycle,
			sessionParticipants,
			sessionStore,
			revocationModule,
			revocationStore,
			simulatedStore().module,
			dpopModule,
			dpopStore,
			transparencyModule,
			transparencyInMemory,
			recorder,
			codeGrantModule,
			wiring,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...keysConfig(),
			...issuerConfig({ url: "https://as.example" }),
			...tokensConfig({ revocation: "denylist" }),
			...clientsConfig([
				confidentialClient({
					id: "app",
					sections: allowancesFor({
						grants: ["authorization_code"],
						scopes: ["read"],
						audiences: ["https://api"],
					}),
				}),
			]),
			...sessionLifecycleConfig(),
			...dpopConfig(),
			...codeGrantConfig(),
		},
		runtime,
	});
	await app.start();
	try {
		const { session } = openedOf(
			await app.get(sessions).open({
				subject: "alice",
				amr: ["hwk", "user"],
				authenticatedAt: runtime.clock.now(),
				provenSince: runtime.clock.now(),
				endsAt: runtime.clock.now() + 3_600_000,
			}),
		);
		const jwk = await exportJWK(held.publicKey);
		const binding = {
			member: "jkt",
			confirmation: await calculateJwkThumbprint(jwk),
			tokenType: "DPoP",
		};
		const code = await app.get(codes).issue({
			clientId: "app",
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
			root: "root-of-the-approval",
			binding,
		});
		/** A fresh proof by the held key, for the token endpoint. */
		const proof = () =>
			new SignJWT({
				jti: randomUUID(),
				htm: "POST",
				htu: "https://as.example/oauth/token",
				iat: Math.floor(Date.now() / 1000),
			})
				.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
				.sign(held.privateKey);
		const redeem = async () => {
			const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					dpop: await proof(),
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: "app",
					client_secret: clientSecret("app"),
					code,
					redirect_uri: "https://app.example/cb",
					code_verifier: verifier,
				}),
			});
			return { status: res.status, body: (await res.json()) as Record<string, unknown> };
		};
		const first = await redeem();
		expect(first).toMatchObject({ status: 200, body: { token_type: "DPoP" } });
		expect((await redeem()).body.error).toBe("invalid_grant");
		const verified = await app.get(accessTokens).verifyAccess(String(first.body.access_token));
		expect(verified.kind).toBe("invalid");
	} finally {
		await app.stop(1000);
	}
});
