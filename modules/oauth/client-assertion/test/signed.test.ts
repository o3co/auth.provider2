import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
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
const runtime = quietRuntime({ clock: { now: () => now } });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = (key: KeyObject, extra: Record<string, unknown> = {}): Jwk => ({
	...(key.export({ format: "jwk" }) as Jwk),
	...extra,
});

async function boot() {
	const beside = defineModule({ name: "beside", replicaSafe: false, takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
		m.provide(spentAssertions).by(() => ({ save: async () => "created" as const })),
	]);
	const keyed = (id: string, sections: Readonly<Record<string, unknown>>) =>
		({ id, kind: "confidential", method: "private_key_jwt", sections }) as const;
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
			]),
		},
		runtime,
	});
	const client = async (id: string) => {
		const found = await app.get(clients).find(id);
		if (!found) throw new Error(`no client ${id}`);
		return found;
	};
	return { checks: app.get(clientAssertion), client };
}

const signed = (key: KeyObject, typ: string, claims: object = {}, alg = "ES256") =>
	new SignJWT({ exp: Math.floor(now / 1000) + 60, ...claims })
		.setProtectedHeader({ alg, typ, kid: "ec" })
		.sign(key);

describe("whether a client holds a key", () => {
	it("holds a key of its own written in, by its thumbprint, that the operator's algorithms read", async () => {
		const { checks, client } = await boot();
		const app = await client("app");
		expect(await checks.holdsKey(app, await thumbprint(jwk(ec.publicKey)))).toBe(true);
		expect(await checks.holdsKey(app, await thumbprint(jwk(other.publicKey)))).toBe(false);
		// RS256 is not taken by default, so the RSA key is read under none: not one of its keys here.
		expect(await checks.holdsKey(app, await thumbprint(jwk(rsa.publicKey)))).toBe(false);
	});

	it("holds none where its keys are at a jwks-uri, as no key set's keys are read here", async () => {
		const { checks, client } = await boot();
		const far = await client("far");
		expect(await checks.holdsKey(far, await thumbprint(jwk(ec.publicKey)))).toBe(false);
	});
});

describe("a JWT a client signed", () => {
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
			reason: "not a JWT",
		});
		const foreign = await signed(other.privateKey, "jwt");
		expect(await checks.verifySignedBy(app, foreign, "jwt")).toEqual({
			kind: "refused",
			reason: "signature",
		});
		const old = await signed(ec.privateKey, "jwt", { exp: Math.floor(now / 1000) - 3600 });
		expect(await checks.verifySignedBy(app, old, "jwt")).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});
});
