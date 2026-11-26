import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { type Clients, clientSources, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, unavailableSwitch } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { type JWTPayload, SignJWT } from "jose";
import { type Jwk, type SpentAssertions, spentAssertions } from "../src/contract.ts";
import { assertionType } from "../src/method/method.ts";
import assertionModule from "../src/module.ts";
import { clientAssertionConfig, clientKeysFor } from "../src/testing.ts";

export type Header = { readonly alg: string; readonly kid?: string };

/** The package composed for its tests, over a clock its tests move (`read`), and the helpers they share. */
export function composed(read: () => number) {
	const issuer = "https://issuer.example";
	const tokenUrl = `${issuer}/oauth/token`;
	const seconds = () => Math.floor(read() / 1000);
	const recorded = recordingLog();
	/** The newest warn line's reason. */
	const lastWarned = () =>
		String(
			recorded
				.lines()
				.filter((line) => line.level === "warn")
				.at(-1)?.fields.reason,
		);
	/** The ids the client sources were asked for. */
	const looked: unknown[] = [];
	const runtime = quietRuntime({
		clock: { now: read },
		random: { bytes: (n) => new Uint8Array(n) },
		log: recorded.log,
	});

	const ecPair = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
	const ec = ecPair();
	const ed = generateKeyPairSync("ed25519");
	const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const jwk = (key: KeyObject, extra: Record<string, unknown> = {}): Jwk => ({
		...(key.export({ format: "jwk" }) as Jwk),
		...extra,
	});

	async function boot({
		keys = [jwk(ec.publicKey, { kid: "ec" })] as readonly Jwk[],
		method = "private_key_jwt",
		issuerUrl = issuer,
		/** Where the token endpoint is; null for none at all. */
		tokenEndpoint = tokenUrl as string | null,
		/** Whether `http`'s public origin is written; the token endpoint has a location either way. */
		publicOrigin = true,
		/** The clients whose section accepts a loose audience. */
		loose = [] as readonly string[],
		/** The operator section's settings. */
		settings = {} as Parameters<typeof clientAssertionConfig>[0],
		/** Where spent assertions are kept; a new place unless given, so a restart can keep it. */
		stand = memoryRecords<true>(read, { shards: 1, perShard: 1 }),
	} = {}) {
		const down = unavailableSwitch<SpentAssertions>("spent assertions");
		const location = defineModule({ name: "token-endpoint", replicaSafe: true, takes: [] }, (m) => [
			m.provide(tokenEndpointLocation).by(() => ({ url: tokenEndpoint ?? undefined })),
		]);
		const source = defineModule({ name: "source", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(clientSources).by(() => ({
				find: async (id) => {
					looked.push(id);
					return undefined;
				},
			})),
		]);
		const spent = defineModule({ name: "spent", replicaSafe: false, takes: [] }, (m) => [
			m
				.provide(spentAssertions)
				.by(() =>
					down.wrap({ save: (name, lifetimeMs) => stand.records.create(name, true, lifetimeMs) }),
				),
		]);
		// A client of a secret method also holds its secret, which clients requires at boot.
		const registeredAs = (id: string) => {
			const sections = clientKeysFor(
				keys,
				loose.includes(id) ? { "accept-loose-audience": true } : {},
			);
			return method === "private_key_jwt"
				? { id, kind: "confidential" as const, method, sections }
				: confidentialClient({ id, method, sections });
		};
		const input = {
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
				source,
			],
			config: {
				...kernelConfig(),
				outbound: {},
				...httpConfig(publicOrigin ? { "public-origin": issuer } : {}),
				...issuerConfig({ url: issuerUrl }),
				...clientAssertionConfig(settings),
				...clientsConfig([
					registeredAs("app"),
					registeredAs("app:twin"),
					confidentialClient({ id: "post" }),
					confidentialClient({ id: "basic", method: "client_secret_basic" }),
					publicClient({ id: "pub" }),
				]),
			},
			runtime,
		};
		const app = await assemble(input);
		return { app, c: app.get(clients), down, input };
	}

	/** The claims of a good assertion, changed as given; a claim given as undefined is left out. */
	const claims = (extra: Record<string, unknown> = {}): JWTPayload =>
		Object.fromEntries(
			Object.entries({
				iss: "app",
				sub: "app",
				aud: issuer,
				exp: seconds() + 60,
				jti: `j-${Math.random()}`,
				...extra,
			}).filter(([, value]) => value !== undefined),
		);
	const sign = (
		payload: JWTPayload,
		key: KeyObject = ec.privateKey,
		header: Header = { alg: "ES256", kid: "ec" },
	) => new SignJWT(payload).setProtectedHeader(header).sign(key);
	/** An assertion signed with a shared secret, which no client key verifies. */
	const signedWithSecret = () =>
		new SignJWT(claims()).setProtectedHeader({ alg: "HS256" }).sign(new Uint8Array(32));
	/** An assertion with these claims and no signature, under alg none. */
	const unsigned = (payload: JWTPayload = claims()) =>
		`${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.`;
	/** A form request; a list gives a field more than once. */
	const asked = (form: Record<string, string | readonly string[]>) =>
		testRequest({
			method: "POST",
			form: new Map(Object.entries(form).map(([k, v]) => [k, [v].flat()])),
		});
	/** A JSON body request. */
	const posted = (json: Record<string, unknown>) => testRequest({ method: "POST", json });
	const presenting = (assertion: string, extra: Record<string, string> = {}) =>
		asked({ client_assertion_type: assertionType, client_assertion: assertion, ...extra });
	const outcome = async (c: Clients, request: ReturnType<typeof asked>) => {
		const result = await c.authenticate(request);
		return result.kind === "authenticated" ? result.client.id : result.reason;
	};
	/** The outcome of an assertion with these claims, signed as given, carrying `form` beside it. */
	const tried = async (
		c: Clients,
		extra: Record<string, unknown> = {},
		form: Record<string, string> = {},
		key?: KeyObject,
		header?: Header,
	) => outcome(c, presenting(await sign(claims(extra), key, header), form));
	return {
		issuer,
		tokenUrl,
		seconds,
		recorded,
		lastWarned,
		looked,
		runtime,
		ecPair,
		ec,
		ed,
		rsa,
		jwk,
		boot,
		claims,
		sign,
		signedWithSecret,
		unsigned,
		asked,
		posted,
		presenting,
		outcome,
		tried,
	};
}
