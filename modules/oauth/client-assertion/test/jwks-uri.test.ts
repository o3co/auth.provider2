import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { clientSources, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { thumbprint } from "@mod/keys";
import outboundModule from "@mod/outbound/module";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { SignJWT } from "jose";
import { afterAll, beforeAll, expect, it } from "vitest";
import { clientAssertion, spentAssertions } from "../src/contract.ts";
import { assertionType } from "../src/method.ts";
import assertionModule from "../src/module.ts";
import { clientAssertionConfig } from "../src/testing.ts";

const issuer = "https://issuer.example";
const tokenUrl = `${issuer}/oauth/token`;
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const publicJwk = (key: KeyObject, kid: string) => ({ ...key.export({ format: "jwk" }), kid });

/** A key set server on loopback, counting what it is asked; `/down` answers 503. */
let fetched = 0;
let served: unknown = { keys: [publicJwk(ec.publicKey, "ec")] };
const server = createServer((request, response) => {
	fetched++;
	if (request.url === "/down") {
		response.writeHead(503).end();
		return;
	}
	response.writeHead(200, { "content-type": "application/json" });
	response.end(JSON.stringify(served));
});
let port = 0;
beforeAll(async () => {
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
const jwksUri = () => `http://127.0.0.1:${port}/jwks`;

/** Clients over outbound reaching the key set server alone; `section` is the client's own, registered or, `fromSource`, a source's. */
async function boot(section: Record<string, unknown>, reach = true, fromSource = false) {
	const record = {
		id: "app",
		kind: "confidential",
		method: "private_key_jwt",
		sections: { "client-assertion": section },
	} as const;
	const source = defineModule({ name: "source", replicaSafe: true, takes: [] }, (m) => [
		m
			.contribute(clientSources)
			.by(() => ({ find: async (id: string) => (id === "app" ? record : undefined) })),
	]);
	const stand = memoryRecords<true>(() => Date.now(), { shards: 1, perShard: 1 });
	const location = defineModule({ name: "token-endpoint", replicaSafe: true, takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: tokenUrl })),
	]);
	const spent = defineModule({ name: "spent", replicaSafe: false, takes: [] }, (m) => [
		m
			.provide(spentAssertions)
			.by(() => ({ save: (name, lifetimeMs) => stand.records.create(name, true, lifetimeMs) })),
	]);
	const app = await assemble({
		modules: [
			http,
			testServer(),
			outboundModule,
			tlsOptionsForTests,
			externalJwtModule,
			clientsModule,
			secretHashModule,
			issuerModule,
			assertionModule,
			spent,
			location,
			...(fromSource ? [source] : []),
			promisesModule,
		],
		config: {
			...kernelConfig(),
			outbound: reach ? { allow: ["127.0.0.1"], "plain-loopback": [`127.0.0.1:${port}`] } : {},
			...httpConfig({ "public-origin": issuer }),
			...issuerConfig({ url: issuer }),
			...clientAssertionConfig(),
			...clientsConfig(fromSource ? [] : [record]),
		},
		runtime: quietRuntime(),
	});
	const claim2 = app
		.get(promises)
		.judgment()
		.find((j) => j.promise === promiseNames.clientToken);
	return { ...app.get(clients), checks: app.get(clientAssertion), claim2 };
}

const assertion = (aud: string = issuer) =>
	new SignJWT({
		iss: "app",
		sub: "app",
		aud,
		exp: Math.floor(Date.now() / 1000) + 60,
		jti: `j-${Math.random()}`,
	})
		.setProtectedHeader({ alg: "ES256", kid: "ec" })
		.sign(ec.privateKey);
const authenticate = async (c: Awaited<ReturnType<typeof boot>>, aud?: string) =>
	c.authenticate(
		testRequest({
			method: "POST",
			form: new Map([
				["client_assertion_type", [assertionType]],
				["client_assertion", [await assertion(aud)]],
			]),
		}),
	);

it("authenticates a client by keys it publishes at its jwks-uri, fetching the set once", async () => {
	const c = await boot({ "jwks-uri": jwksUri() });
	const before = fetched;
	for (let i = 0; i < 2; i++) {
		expect(await authenticate(c)).toMatchObject({ kind: "authenticated", client: { id: "app" } });
	}
	expect(fetched - before).toBe(1);
});

it("refuses a source's client naming a jwks-uri, fetching nothing: a source's keys are written in alone (R8, §3.11)", async () => {
	const c = await boot({ "jwks-uri": jwksUri() }, true, true);
	const before = fetched;
	expect(await authenticate(c)).toMatchObject({ kind: "refused" });
	expect(fetched - before).toBe(0);
});

it("takes a loose audience for a registered client that accepts one, and for a source's client never (§0.2)", async () => {
	const keys = { keys: [publicJwk(ec.publicKey, "ec")], "accept-loose-audience": true };
	const registered = await boot(keys);
	expect(await authenticate(registered, tokenUrl)).toMatchObject({ kind: "authenticated" });
	const sourced = await boot(keys, true, true);
	expect(await authenticate(sourced, tokenUrl)).toMatchObject({ kind: "refused" });
	expect(await authenticate(sourced)).toMatchObject({ kind: "authenticated" });
});

it("stands on claim 2 as composed: broken by a registered jwks-uri or loose audience, by its place and field; held for a source's", async () => {
	expect((await boot({ "jwks-uri": jwksUri() })).claim2).toMatchObject({
		held: false,
		breaking: [
			{
				by: "client-assertion",
				setting: "clients.registered.0.sections.client-assertion.jwks-uri",
			},
		],
	});
	const loose = { keys: [publicJwk(ec.publicKey, "ec")], "accept-loose-audience": true };
	expect((await boot(loose)).claim2).toMatchObject({
		held: false,
		breaking: [
			{
				by: "client-assertion",
				setting: "clients.registered.0.sections.client-assertion.accept-loose-audience",
			},
		],
	});
	// A source's client weakens nothing: its keys are written in, its audience strict.
	expect((await boot(loose, true, true)).claim2).toMatchObject({ held: true, breaking: [] });
	expect((await boot({ "jwks-uri": jwksUri() }, true, true)).claim2).toMatchObject({ held: true });
});

it("answers the key of the set its assertion was verified with, naming the client", async () => {
	const c = await boot({ "jwks-uri": jwksUri() });
	const answer = await authenticate(c);
	if (answer.kind !== "authenticated") throw new Error(answer.reason);
	// Fetched from the client's key set, so not a key written in its record.
	const verified = c.checks.verifiedOf(answer.proof, answer.client);
	expect(verified).toEqual({
		client: "app",
		key: publicJwk(ec.publicKey, "ec"),
		thumbprint: await thumbprint(publicJwk(ec.publicKey, "ec")),
	});
	expect(verified?.written).toBeUndefined();
});

it("refuses a key its jwks-uri does not publish [rfc7523-3-u] [rfc7521-5.2-n]", async () => {
	served = {
		keys: [publicJwk(generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey, "ec")],
	};
	try {
		const c = await boot({ "jwks-uri": jwksUri() });
		expect(await authenticate(c)).toMatchObject({ kind: "refused", reason: "bad_credentials" });
	} finally {
		served = { keys: [publicJwk(ec.publicKey, "ec")] };
	}
});

it("is unavailable while the jwks-uri gives no key set", async () => {
	const c = await boot({ "jwks-uri": `http://127.0.0.1:${port}/down` });
	await expect(authenticate(c)).rejects.toSatisfy(isUnavailable);
});

it("refuses boot for a client whose jwks-uri outbound's policy refuses", async () => {
	await expect(boot({ "jwks-uri": jwksUri() }, false)).rejects.toMatchObject({
		refusals: [
			{
				where: "clients.registered.0.sections.client-assertion",
				reason: expect.stringMatching(
					/refuses the jwks-uri: not-allowed: name the host in outbound\.allow, or set outbound\.allow-any-public; plain http also needs its host:port in outbound\.plain-loopback, or, for a URL of your own configuration on a private network, in outbound\.plain-internal$/,
				),
			},
		],
	});
});

it("refuses boot for a client with both written keys and a jwks-uri, or a jwks-uri that is no URL", async () => {
	const keys = [publicJwk(ec.publicKey, "ec")];
	for (const section of [
		{ keys, "jwks-uri": jwksUri() },
		{ "jwks-uri": "not a url" },
		{ "jwks-uri": "ftp://keys.example/jwks" },
	]) {
		await expect(boot(section), JSON.stringify(section)).rejects.toBeInstanceOf(BootRefused);
	}
});
