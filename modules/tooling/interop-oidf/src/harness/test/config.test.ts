import { describe, expect, it } from "vitest";
import { ledger } from "../../deviations/deviations.ts";
import { expectedFor } from "../../expected/expected.ts";
import { suiteOrigin } from "../../suite/suite.ts";
import {
	browserOf,
	callbacksOf,
	clientOf,
	denied,
	planA,
	planConfig,
	scopes,
	variantA,
} from "./config.ts";

const at = {
	alias: "nextgen-a",
	issuer: "https://host.docker.internal:4443",
	screen: "https://host.docker.internal:4444",
	resource: "https://host.docker.internal:4445/resource",
};

describe("what the harness gives the suite", () => {
	it("registers each client by one ES256 key of its own, at the suite's two callbacks, allowed both its scopes, bound to DPoP", () => {
		const c = clientOf("oidf-client-1", at.alias);
		const [priv] = c.jwks.keys;
		expect(priv).toMatchObject({ kty: "EC", crv: "P-256", kid: "oidf-client-1-key", alg: "ES256" });
		expect(priv?.d).toBeTypeOf("string");
		const sections = JSON.stringify(c.registered.sections);
		expect(sections).not.toContain(`"d":`);
		expect(c.registered).toMatchObject({
			id: c.id,
			kind: "confidential",
			method: "private_key_jwt",
		});
		expect(sections).toContain(JSON.stringify([...callbacksOf(at.alias)]));
		expect(callbacksOf(at.alias)).toEqual([
			`${suiteOrigin}/test/a/nextgen-a/callback`,
			`${suiteOrigin}/test/a/nextgen-a/callback?dummy1=lorem&dummy2=ipsum`,
		]);
		expect(sections).toContain(JSON.stringify(["openid", "email"]));
		expect(c.registered.sections).toMatchObject({ "sender-binding": { required: true } });
		expect(clientOf("oidf-client-2", at.alias).jwks.keys[0]?.x).not.toBe(priv?.x);
	});

	it("asks more than one scope, each client alike, and names the server, the resource and the browser", () => {
		const config = planConfig(at, [clientOf("c1", at.alias), clientOf("c2", at.alias)]);
		expect(scopes.length).toBeGreaterThan(1);
		expect(config.client.scope).toBe("openid email");
		expect(config.client2).toMatchObject({
			client_id: "c2",
			scope: "openid email",
			dpop_signing_alg: "ES256",
		});
		expect(config.server.discoveryUrl).toBe(`${at.issuer}/.well-known/openid-configuration`);
		expect(config.resource.resourceUrl).toBe(at.resource);
		expect(config.browser).toEqual(browserOf(at.screen));
		// The suite moves each of a module's overrides up whole: #3's browser is the deny one.
		expect(config.override).toEqual(
			Object.fromEntries(denied.map((name) => [name, { browser: browserOf(at.screen, "deny") }])),
		);
		expect(browserOf(at.screen, "deny")).not.toEqual(config.browser);
	});

	it("approves on the authorization page, or denies for a module told so, then fills a refusal's placeholder on the page it was sent on to, in the one entry the suite opens", () => {
		const entries = browserOf(at.screen);
		expect(entries).toHaveLength(1);
		const [entry] = entries;
		expect(entry?.match).toBe(`${at.screen}/authorize*`);
		expect(entry?.tasks).toEqual([
			{
				task: "Approve",
				match: `${at.screen}/authorize*`,
				optional: true,
				commands: [["click", "id", "approve", "optional"]],
			},
			{
				task: "Show the refusal",
				match: `${at.screen}/refused*`,
				optional: true,
				commands: [["wait", "id", "refused", 10, "refused", "update-image-placeholder-optional"]],
			},
		]);
		expect(browserOf(at.screen, "deny")[0]?.tasks[0]).toMatchObject({
			task: "Deny",
			commands: [["click", "id", "deny", "optional"]],
		});
	});

	it("runs the plan and variant run A's expected results name, every module the denied one among them", () => {
		const entries = expectedFor(
			"a",
			ledger().map((d) => d.key),
		);
		expect(planA).toBe("fapi2-message-signing-final-test-plan");
		for (const e of entries) expect(e.variant).toEqual(variantA);
		for (const name of denied) expect(entries.map((e) => e.test)).toContain(name);
	});
});
