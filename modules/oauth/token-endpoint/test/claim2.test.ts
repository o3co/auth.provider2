import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { authMethods } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { grants } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { issuer } from "@mod/issuer";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { promiseNames, promises, type Stance, stances } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { testScryptHash } from "@mod/secret-hash/testing";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect, it } from "vitest";
import { grantCaller } from "../src/testing.ts";
import { clientTokens, clientTokensModule, endpointConfig, endpointModules } from "./deployment.ts";

const seen = contract<readonly Stance[]>("test.stances");
const probe = defineModule({ name: "probe", replicaSafe: true, takes: [stances] }, (m) => [
	m.provide(seen).by((c) => c.collect(stances)),
]);
const claim2 = (all: readonly Stance[]) =>
	all.filter((s) => s.promise === promiseNames.clientToken);

/** The fixture grant, declaring its client's token held to its assertion's key. */
const heldTokens = defineModule(
	{ name: "held-tokens", replicaSafe: true, takes: [issuer] },
	(m) => [
		m.contribute(grants).by(async (c) => ({
			...clientTokens((await c.get(issuer)).url),
			keyHold: "assertion" as const,
		})),
	],
);
/** A method contributed beside the built-in ones, declaring no key held. */
const silentMethod = defineModule({ name: "silent-method", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(authMethods).by(() => ({
		name: "client_secret_jwt",
		signingAlgorithms: ["HS256"],
		claimed: () => undefined,
		verify: async () => undefined,
	})),
]);
const pub = { id: "pub", kind: "public", method: "none" };
const secret = {
	id: "c1",
	kind: "confidential",
	method: "client_secret_basic",
	sections: { "client-secret": { hash: testScryptHash("s3cret") } },
};

/** The endpoint's composition, its fixture grant declaring a hold unless told, and what promises judges claim 2. */
async function judged(
	p: { registered?: unknown[]; held?: boolean; extra?: readonly Module[] } = {},
) {
	const base = endpointModules(clientAllowanceModule, rateLimitStandIn, auditStandIn().module);
	const modules = [
		...(p.held === false ? base : base.filter((m) => m !== clientTokensModule)),
		...(p.held === false ? [] : [heldTokens]),
		promisesModule,
		probe,
		...(p.extra ?? []),
	];
	const app = await assemble({
		modules,
		config: { ...endpointConfig(), clients: { registered: p.registered ?? [pub] } },
		runtime: quietRuntime(),
	});
	const judgment = app
		.get(promises)
		.judgment()
		.find((j) => j.promise === promiseNames.clientToken);
	return { judgment, stances: claim2(app.get(seen)) };
}

it("stands on claim 2 from the token endpoint's module and from its test caller alike", async () => {
	const { stances: fromModule } = await judged();
	expect(fromModule).toContainEqual(expect.objectContaining({ by: "token-endpoint", holds: true }));
	const app = await assemble({
		modules: [
			http,
			testServer(),
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			probe,
		],
		config: { ...kernelConfig(), ...httpConfig(), clients: { registered: [pub] } },
		runtime: quietRuntime(),
	});
	expect(claim2(app.get(seen))).toContainEqual(
		expect.objectContaining({ by: "token-endpoint", holds: true }),
	);
});

it("holds claim 2 where every grant declares its hold and no client or method weakens it", async () => {
	const { judgment } = await judged();
	expect(judgment).toMatchObject({ held: true, breaking: [] });
});

it("does not hold it for a grant declaring no hold, a registered shared secret, or a method holding no key, each named", async () => {
	expect((await judged({ held: false })).judgment).toMatchObject({
		held: false,
		breaking: [expect.objectContaining({ by: "token-endpoint" })],
	});
	expect((await judged({ registered: [pub, secret] })).judgment).toMatchObject({
		held: false,
		breaking: [{ by: "clients", setting: "clients.registered.1.method" }],
	});
	expect((await judged({ extra: [silentMethod] })).judgment).toMatchObject({
		held: false,
		breaking: [
			expect.objectContaining({
				by: "clients",
				reason: expect.stringMatching(/client_secret_jwt/),
			}),
		],
	});
});
