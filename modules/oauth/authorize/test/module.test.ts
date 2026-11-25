import { acr } from "@mod/acr";
import { approvals, statementItems } from "@mod/approvals";
import { claimsSelections } from "@mod/claims-selection";
import { clientAssertion } from "@mod/client-assertion";
import { clients } from "@mod/clients";
import { codes } from "@mod/code-grant";
import { overHttp } from "@mod/front-core-wire";
import { type Route, routes } from "@mod/http";
import { issuer, type MetadataItem, metadata } from "@mod/issuer";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { delegation } from "@mod/refresh";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { accessTokenIssuance } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { jarReservations, signUpOffers, withoutPasskey } from "../src/contract.ts";
import authorize from "../src/module.ts";
import { authorizeConfig } from "../src/testing.ts";

const seen = contract<{
	readonly routes: readonly Route[];
	readonly metadata: readonly MetadataItem[];
	readonly items: readonly unknown[];
}>("test.seen");

const fakes = defineModule(
	{ name: "fakes", replicaSafe: true, takes: [routes, metadata, statementItems] },
	(m) => [
		m
			.contribute(statementItems)
			.by(() => ({ purpose: "authorization", names: ["dpop_jkt"], by: "fakes" })),
		m.provide(clients).by(() => ({}) as never),
		m.provide(clientAssertion).by(() => ({}) as never),
		m.provide(approvals).by(() => ({}) as never),
		m.provide(jarReservations).by(() => ({}) as never),
		m.provide(accessTokenIssuance).by(() => ({}) as never),
		m.provide(sessions).by(() => ({}) as never),
		m.provide(codes).by(() => ({ issuesIdTokens: () => false }) as never),
		m.provide(claimsSelections).by(() => ({}) as never),
		m.provide(acr).by(() => ({ current: () => undefined }) as never),
		m.provide(delegation).by(() => ({ lifetimeMs: 86_400_000 })),
		m.provide(senderBinding).by(() => ({}) as never),
		m
			.provide(issuer)
			.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
		m.provide(seen).by(async (c) => ({
			routes: await c.collect(routes),
			metadata: await c.collect(metadata),
			items: await c.collect(statementItems),
		})),
	],
);
const answer = (name: string) =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(withoutPasskey).by(() => ({ allows: async () => true })),
	]);
const boot = (more: readonly Module[] = []) =>
	assemble({
		modules: [fakes, authorize, ...more],
		config: { ...kernelConfig(), ...authorizeConfig() },
		runtime: quietRuntime(),
	});

describe("authorize, composed", () => {
	it("serves the start, publishes the screen as the authorization endpoint, and fills every item but dpop_jkt", async () => {
		const app = await boot();
		const { routes: served, metadata: items, items: filled } = await app.get(seen);
		expect(served.map((r) => `${r.method} ${r.path}`)).toEqual([
			`POST ${overHttp.operations.loginStart.path}`,
			`POST ${overHttp.operations.loginFinish.path}`,
		]);
		expect(items).toContainEqual({
			name: "authorization_endpoint",
			value: "https://login.example/authorize",
		});
		expect(items).toContainEqual({ name: "response_modes_supported", value: ["form_post"] });
		const own = filled.find((d) => (d as { by: string }).by === "authorize") as { names: string[] };
		expect(own.names).not.toContain("dpop_jkt");
		expect(own.names).toContain("jar_hash");
	});

	it("refuses boot where no module fills dpop_jkt", async () => {
		const bare = defineModule({ name: "bare", replicaSafe: true, takes: [routes] }, (m) => [
			m.provide(clients).by(() => ({}) as never),
			m.provide(clientAssertion).by(() => ({}) as never),
			m.provide(approvals).by(() => ({}) as never),
			m.provide(jarReservations).by(() => ({}) as never),
			m.provide(accessTokenIssuance).by(() => ({}) as never),
			m.provide(sessions).by(() => ({}) as never),
			m.provide(codes).by(() => ({ issuesIdTokens: () => false }) as never),
			m.provide(claimsSelections).by(() => ({}) as never),
			m.provide(acr).by(() => ({ current: () => undefined }) as never),
			m.provide(delegation).by(() => ({ lifetimeMs: 86_400_000 })),
			m.provide(senderBinding).by(() => ({}) as never),
			m
				.provide(issuer)
				.by(() => ({ url: "https://issuer.example", endpointOrigin: "https://issuer.example" })),
			m
				.provide(seen)
				.by(async (c) => ({ routes: await c.collect(routes), metadata: [], items: [] })),
		]);
		const refused = await assemble({
			modules: [bare, authorize],
			config: { ...kernelConfig(), ...authorizeConfig() },
			runtime: quietRuntime(),
		}).then(
			() => [],
			(error: unknown) =>
				BootRefused.is(error) ? error.refusals.map((r) => r.reason) : [String(error)],
		);
		expect(refused).toEqual([
			expect.stringMatching(/no module fills the authorization's dpop_jkt/),
		]);
	});

	it("refuses boot with two answers to a person with no passkey, or two sign-ups offered", async () => {
		const refusedOf = (more: readonly Module[]) =>
			boot(more).then(
				() => [],
				(error: unknown) =>
					BootRefused.is(error) ? error.refusals.map((r) => r.reason) : [String(error)],
			);
		expect(await refusedOf([answer("a1"), answer("a2")])).toEqual([
			expect.stringMatching(/more than one answer/),
		]);
		const offer = (name: string) =>
			defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
				m.contribute(signUpOffers).by(() => ({ by: name })),
			]);
		expect(await refusedOf([offer("s1"), offer("s2")])).toEqual([
			expect.stringMatching(/more than one sign-up is offered/),
		]);
		// Offered, a sign-up needs an answer to a person with no passkey, which allows it per T.
		expect(await refusedOf([offer("s1")])).toEqual([
			expect.stringMatching(/sign-up is offered, but no answer/),
		]);
		await expect(boot([offer("s1"), answer("a1")])).resolves.toBeDefined();
	});
});
