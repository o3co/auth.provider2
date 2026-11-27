import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { clientSources, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { thumbprint } from "@mod/keys";
import outboundModule from "@mod/outbound/module";
import secretHashModule from "@mod/secret-hash/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { clientAssertion, type Jwk, spentAssertions } from "../src/contract.ts";
import assertionModule from "../src/module.ts";
import { clientKeysFor } from "../src/testing.ts";

const issuer = "https://issuer.example";
const now = 1_800_000_000_000;
const recorded = recordingLog();
const runtime = quietRuntime({ clock: { now: () => now }, log: recorded.log });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = (key: KeyObject, extra: Record<string, unknown> = {}): Jwk => ({
	...(key.export({ format: "jwk" }) as Jwk),
	...extra,
});

async function boot() {
	const keyed = (id: string, sections: Readonly<Record<string, unknown>>) =>
		({ id, kind: "confidential", method: "private_key_jwt", sections }) as const;
	const beside = defineModule({ name: "beside", replicaSafe: false, takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
		m.provide(spentAssertions).by(() => ({ save: async () => "created" as const })),
		// A client from a source, of the registry version it came from.
		m.contribute(clientSources).by(() => ({
			find: async (id) =>
				id === "listed"
					? { ...keyed(id, clientKeysFor([jwk(ec.publicKey, { kid: "ec" })])), version: 9 }
					: id === "fetched"
						? keyed(id, { "client-assertion": { "jwks-uri": "https://keys.example/jwks" } })
						: undefined,
		})),
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
			beside,
		],
		config: {
			...kernelConfig(),
			outbound: { allow: ["keys.example"] },
			...httpConfig({ "public-origin": issuer }),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				keyed("app", clientKeysFor([jwk(ec.publicKey, { kid: "ec" }), jwk(rsa.publicKey)])),
				keyed("far", { "client-assertion": { "jwks-uri": "https://keys.example/jwks" } }),
				// Two keys a JWT naming no kid fits alike.
				keyed("twin", clientKeysFor([jwk(ec.publicKey), jwk(other.publicKey)])),
				// An RSA key that names RS256: never read under PS256, the default.
				keyed("rs", clientKeysFor([jwk(rsa.publicKey, { alg: "RS256" })])),
			]),
		},
		runtime,
	});
	const client = async (id: string) => {
		const found = await app.get(clients).find(id);
		if (!found) throw new Error(`no client ${id}`);
		return found;
	};
	return { checks: app.get(clientAssertion), client, clients: app.get(clients) };
}

const signed = (key: KeyObject, typ: string, claims: object = {}, alg = "ES256") =>
	new SignJWT({ exp: Math.floor(now / 1000) + 60, ...claims })
		.setProtectedHeader({ alg, typ, kid: "ec" })
		.sign(key);

describe("a JWT a client signed", () => {
	it("is refused for a source's client naming a jwks-uri, its keys never fetched: a source's keys are written in alone (R8, §3.11)", async () => {
		const { checks, client } = await boot();
		const fetched = await client("fetched");
		const jwt = await signed(ec.privateKey, "jwt");
		expect(await checks.verifySignedBy(fetched, jwt, "jwt")).toEqual({
			kind: "refused",
			reason: "not signed by the client",
		});
	});

	it("is the client's, under the `typ` asked, with its claims", async () => {
		const { checks, client } = await boot();
		const app = await client("app");
		const jwt = await signed(ec.privateKey, "oauth-authz-req+jwt", { scope: "read" });
		expect(await checks.verifySignedBy(app, jwt, "oauth-authz-req+jwt")).toMatchObject({
			kind: "signed",
			claims: { scope: "read" },
		});
	});

	it("is refused under another `typ`, another key, or past its end", async () => {
		const { checks, client } = await boot();
		const app = await client("app");
		const typed = await signed(ec.privateKey, "jwt");
		expect(await checks.verifySignedBy(app, typed, "oauth-authz-req+jwt")).toEqual({
			kind: "refused",
			reason: "not of the typ asked",
		});
		// A signature by another key, and a key the client does not hold: one answer, as the sender may be anyone.
		const foreign = await signed(other.privateKey, "jwt");
		const unheld = await new SignJWT({ exp: Math.floor(now / 1000) + 60 })
			.setProtectedHeader({ alg: "ES256", typ: "jwt", kid: "not-the-clients" })
			.sign(ec.privateKey);
		for (const jwt of [foreign, unheld])
			expect(await checks.verifySignedBy(app, jwt, "jwt")).toEqual({
				kind: "refused",
				reason: "not signed by the client",
			});
		// Two keys that fit: the same answer, so how many keys fit is not told either.
		const unnamed = await new SignJWT({ exp: Math.floor(now / 1000) + 60 })
			.setProtectedHeader({ alg: "ES256", typ: "jwt" })
			.sign(ec.privateKey);
		expect(await checks.verifySignedBy(await client("twin"), unnamed, "jwt")).toEqual({
			kind: "refused",
			reason: "not signed by the client",
		});
		const lasting = await signed(ec.privateKey, "jwt", { exp: undefined });
		expect(await checks.verifySignedBy(app, lasting, "jwt")).toEqual({
			kind: "refused",
			reason: "no exp that is a time",
		});
		const old = await signed(ec.privateKey, "jwt", { exp: Math.floor(now / 1000) - 3600 });
		expect(await checks.verifySignedBy(app, old, "jwt")).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});
});

describe("a request object's algorithm, by default FAPI 2.0's", () => {
	const typ = "oauth-authz-req+jwt";
	const by = (key: KeyObject, alg: string) =>
		new SignJWT({ exp: Math.floor(now / 1000) + 60 }).setProtectedHeader({ alg, typ }).sign(key);

	it("takes PS256 by an RSA key naming no alg, and refuses RS256, ES384 and ES512 unless named", async () => {
		const { checks, client } = await boot();
		const app = await client("app");
		expect(await checks.verifySignedBy(app, await by(rsa.privateKey, "PS256"), typ)).toMatchObject({
			kind: "signed",
		});
		expect(await checks.verifySignedBy(app, await by(rsa.privateKey, "RS256"), typ)).toEqual({
			kind: "refused",
			reason: "algorithm",
		});
		for (const [curve, alg] of [
			["P-384", "ES384"],
			["P-521", "ES512"],
		] as const) {
			const key = generateKeyPairSync("ec", { namedCurve: curve }).privateKey;
			expect(await checks.verifySignedBy(app, await by(key, alg), typ), alg).toEqual({
				kind: "refused",
				reason: "algorithm",
			});
		}
	});

	it("never reads a key naming RS256 under PS256", async () => {
		const { checks, client } = await boot();
		const rs = await client("rs");
		expect(await checks.verifySignedBy(rs, await by(rsa.privateKey, "PS256"), typ)).toEqual({
			kind: "refused",
			reason: "not signed by the client",
		});
	});
});

describe("the key a client's assertion was verified with", () => {
	const presented = (assertion: string) =>
		testRequest({
			method: "POST",
			form: new Map([
				["client_assertion_type", ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]],
				["client_assertion", [assertion]],
			]),
		});
	const assertion = (key: KeyObject, jti: string, id = "app") =>
		new SignJWT({ iss: id, sub: id, aud: issuer, jti, exp: Math.floor(now / 1000) + 60 })
			.setProtectedHeader({ alg: "ES256", kid: "ec" })
			.sign(key);

	it("is what the authentication verified: the key, its thumbprint and the client's registry version", async () => {
		const { checks, clients: c, client } = await boot();
		const answer = await c.authenticate(presented(await assertion(ec.privateKey, "j1")));
		if (answer.kind !== "authenticated") throw new Error(answer.reason);
		const verified = checks.verifiedOf(answer.proof, answer.client);
		// A key written in the client's record, not fetched from a key set.
		expect(verified).toEqual({
			client: "app",
			key: jwk(ec.publicKey, { kid: "ec" }),
			thumbprint: await thumbprint(jwk(ec.publicKey)),
			written: true,
		});
		expect(Object.isFrozen(verified)).toBe(true);
		// Read for another client, it is none: a proof is its client's alone.
		expect(checks.verifiedOf(answer.proof, await client("far"))).toBeUndefined();
	});

	it("names the registry version a client from a source came from", async () => {
		const { checks, clients: c } = await boot();
		const answer = await c.authenticate(presented(await assertion(ec.privateKey, "j2", "listed")));
		if (answer.kind !== "authenticated") throw new Error(answer.reason);
		expect(checks.verifiedOf(answer.proof, answer.client)).toMatchObject({
			client: "listed",
			version: 9,
		});
	});

	it("is none for a proof this module did not make, however it is shaped", async () => {
		const { checks } = await boot();
		const forged = {
			key: jwk(other.publicKey),
			thumbprint: await thumbprint(jwk(other.publicKey)),
		};
		const app = await (await boot()).client("app");
		for (const proof of [undefined, { ...forged, client: "app" }, "k"])
			expect(checks.verifiedOf(proof, app)).toBeUndefined();
	});

	it("logs each refusal for the operator by client, typ and the detail the sender is not told", async () => {
		const { checks, client } = await boot();
		const app = await client("app");
		const logged = () =>
			recorded
				.lines()
				.filter((line) => line.event === "client-assertion.jwt_refused")
				.map(({ level, fields }) => ({ level, fields }));
		const before = logged().length;
		const foreign = await signed(other.privateKey, "oauth-authz-req+jwt");
		const unheld = await new SignJWT({ exp: Math.floor(now / 1000) + 60 })
			.setProtectedHeader({ alg: "ES256", typ: "jwt", kid: "not-the-clients" })
			.sign(ec.privateKey);
		const unnamed = await new SignJWT({ exp: Math.floor(now / 1000) + 60 })
			.setProtectedHeader({ alg: "ES256", typ: "jwt" })
			.sign(ec.privateKey);
		const answers = [
			await checks.verifySignedBy(app, foreign, "oauth-authz-req+jwt"),
			await checks.verifySignedBy(app, unheld, "jwt"),
			await checks.verifySignedBy(await client("twin"), unnamed, "jwt"),
		];
		// The sender is told one word for all three.
		expect(answers).toEqual(Array(3).fill({ kind: "refused", reason: "not signed by the client" }));
		expect(logged().slice(before)).toEqual([
			{ level: "warn", fields: { client: "app", typ: "oauth-authz-req+jwt", reason: "signature" } },
			{ level: "warn", fields: { client: "app", typ: "jwt", reason: "no key fits" } },
			{ level: "warn", fields: { client: "twin", typ: "jwt", reason: "more than one key fits" } },
		]);
		// A JWT taken logs nothing.
		await checks.verifySignedBy(app, await signed(ec.privateKey, "jwt"), "jwt");
		expect(logged()).toHaveLength(before + 3);
	});
});
