import { generateKeyPairSync } from "node:crypto";
import { type ClaimScopes, claimScopes, claimsSelections } from "@mod/claims-selection";
import { type IdTokenMaker, idTokens } from "@mod/code-grant";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig, testHolder } from "@mod/keys/testing";
import { promiseNames, stances } from "@mod/promises";
import { subjectAttributes } from "@mod/subject-attributes";
import { afterEach, expect, it } from "vitest";
import oidcModule from "../src/module.ts";

/** The bundle's record, as the endpoint hands it on. */
const placed = { id: "r-bundle", acceptedAt: 1_800_000_001_500 };

let stop = async () => {};
afterEach(() => stop());

const seen = contract<{
	readonly items: readonly MetadataItem[];
	readonly makers: readonly IdTokenMaker[];
	readonly scopes: readonly ClaimScopes[];
}>("seen");
const reader = defineModule(
	{ name: "reader", replicaSafe: true, takes: [metadata, idTokens, claimScopes, stances, keys] },
	(m) => [
		m
			.contribute(stances)
			.by(() => ({ promise: promiseNames.coreContained, holds: true, by: "reader" })),
		m.provide(seen).by(async (c) => ({
			items: await c.collect(metadata),
			makers: await c.collect(idTokens),
			scopes: await c.collect(claimScopes),
		})),
	],
);
const standIns = defineModule({ name: "stand-ins", replicaSafe: true, takes: [] }, (m) => [
	m.provide(subjectAttributes).by(() => ({
		of: async () => ({ kind: "known", vouched: true, attributes: { name: "Alice" } }),
	})),
	m.provide(claimsSelections).by(() => ({ forCode: async () => undefined }) as never),
]);
const ed25519 = generateKeyPairSync("ed25519").privateKey;

async function serve(authority?: object, log = quietRuntime().log) {
	const app = await assemble({
		modules: [
			http,
			testServer(),
			issuerModule,
			keysModule,
			testHolder({ ed: ed25519 }),
			standIns,
			reader,
			oidcModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...keysConfig(authority ? { authority: authority as never } : {}),
		},
		runtime: quietRuntime({ log }),
	});
	await app.start();
	stop = () => app.stop(1000);
	return app;
}

it("makes an ID token the authority's ring verifies under JWT, of the issuer, for the code's client", async () => {
	const app = await serve();
	const [maker] = app.get(seen).makers;
	if (!maker) throw new Error("no ID token maker");
	const part = await maker.part({
		subject: "alice",
		clientId: "app",
		nonce: "n",
		amr: ["pop", "user"],
		scope: ["openid", "profile"],
		session: "sid",
		code: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		esig: "e",
		apr: { shard: "s1", n: 1 },
		approvedAt: Date.now(),
	});
	const ready = await part.prepare(Date.now());
	const jws = await part.sign(ready.prepared, "h.p1.s", placed);
	const checked = await app.get(keys).verify("authority", jws, "JWT");
	expect(checked).toMatchObject({
		kind: "valid",
		claims: { iss: "https://as.example", sub: "alice", aud: "app", name: "Alice" },
	});
});

it("names itself in the metadata: its scopes and claims, the claims parameter, public subjects, and the ring's algorithm", async () => {
	const app = await serve();
	const items = Object.fromEntries(app.get(seen).items.map((item) => [item.name, item.value]));
	expect(items).toMatchObject({
		scopes_supported: ["openid", "profile", "email", "groups"],
		claims_supported: ["sub", "name", "picture", "email", "email_verified", "groups"],
		claims_parameter_supported: true,
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["ES256"],
	});
	expect(app.get(seen).scopes.map((s) => [s.scopeOf("email"), s.scopeOf("phone_number")])).toEqual([
		["email", undefined],
	]);
});

it("refuses boot where the authority's ring signs by an algorithm not of SHA-256, saying how to set it", async () => {
	await expect(serve({ signing: { kid: "ed", alg: "EdDSA" } })).rejects.toMatchObject({
		refusals: [
			expect.objectContaining({
				reason: expect.stringContaining("set the authority's ring to an algorithm of SHA-256"),
			}),
		],
	});
});

it("warns at each boot where the ring's next key signs by an algorithm not of SHA-256", async () => {
	const logged = recordingLog();
	await serve(
		{ signing: { kid: "test", alg: "ES256" }, next: { kid: "ed", alg: "EdDSA" } },
		logged.log,
	);
	expect(logged.lines()).toContainEqual(
		expect.objectContaining({ event: "oidc.next_key_alg_refused", fields: { alg: "EdDSA" } }),
	);
});
