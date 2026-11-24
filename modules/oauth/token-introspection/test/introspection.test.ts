import { clientSecret } from "@mod/clients/testing";
import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { senderBindings } from "@mod/sender-binding";
import { type AccessCondition, accessConditions } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { clockNow, later, serve } from "./serve.ts";

describe("introspection", () => {
	it("tells a resource server sharing the audience about an active token [rfc7662-2.2-a]", async () => {
		const s = await serve();
		const answer = await s.post("api", { token: await s.issue() });
		expect(answer.status).toBe(200);
		expect(answer.headers.get("cache-control")).toBe("no-store");
		expect(answer.json).toMatchObject({
			active: true,
			iss: "https://issuer.example",
			client_id: "app",
			sub: "app",
			aud: "https://api",
			scope: "read",
		});
	});

	it("tells the subject's kind its token carries, so a resource server tells a client's token from a person's of the same name", async () => {
		const s = await serve();
		const client = await s.post("api", { token: await s.issue() });
		expect(client.json).toMatchObject({ active: true, sub: "app", o3co_subject_kind: "client" });
		const person = await s.post("api", {
			token: await s.issue(undefined, { subjectKind: "user" }),
		});
		expect(person.json).toMatchObject({ active: true, sub: "app", o3co_subject_kind: "user" });
	});

	it("answers a revoked access token inactive and nothing more [rfc7662-4-d]", async () => {
		const s = await serve();
		const token = await s.issue();
		expect(await s.active(token)).toBe(true);
		expect((await s.revoke(token)).kind).toBe("revoked");
		expect((await s.post("api", { token })).json).toEqual({ active: false });
	});

	it("never answers the token it introspects, nor its signature, only what it tells of it [oidc-core-16.4-a]", async () => {
		const s = await serve();
		const token = await s.issue();
		const answer = await s.post("api", { token });
		expect(answer.json.active).toBe(true);
		for (const part of [token, token.split(".")[2] ?? token]) {
			expect(JSON.stringify(answer.json)).not.toContain(part);
		}
		const told = [
			"active",
			"iss",
			"sub",
			"o3co_subject_kind",
			"client_id",
			"aud",
			"scope",
			"exp",
			"token_type",
			"cnf",
		];
		for (const name of Object.keys(answer.json)) expect(told).toContain(name);
	});

	it("finds an access token whatever type its hint names [rfc7662-2.1-b]", async () => {
		const s = await serve();
		const token = await s.issue();
		for (const token_type_hint of ["access_token", "refresh_token", "id_token", "unknown"]) {
			const answer = await s.post("api", { token, token_type_hint });
			expect(answer.json, token_type_hint).toMatchObject({ active: true, sub: "app" });
		}
	});

	it("answers an access token active only before its expiry [rfc7662-4-b]", async () => {
		const s = await serve();
		const token = await s.issue({ notAfter: clockNow() + 60_000 });
		const exp = Number((await s.post("app", { token })).json.exp);
		expect(exp * 1000).toBeGreaterThan(clockNow());
		later(exp * 1000 - 1 - clockNow());
		expect(await s.active(token)).toBe(true);
		later(1);
		expect(await s.active(token)).toBe(false);
	});

	it("tells a resource server how an access token is bound", async () => {
		/** The binding kind the bound token is issued with, so tokens reads its member back. */
		const keyed = defineModule({ name: "keyed-binding", replicaSafe: true, takes: [] }, (m) => [
			m
				.contribute(senderBindings)
				.by(() => ({ member: "key", tokenType: "Keyed", read: async () => ({ kind: "absent" }) })),
		]);
		const s = await serve({ extra: [keyed] });
		const binding = { member: "key", confirmation: "k1", tokenType: "Keyed" };
		const bound = await s.post("app", { token: await s.issue({ binding }) });
		expect(bound.json).toMatchObject({ active: true, token_type: "Keyed", cnf: { key: "k1" } });
		const bearer = await s.post("app", { token: await s.issue() });
		expect(bearer.json).toMatchObject({ active: true, token_type: "Bearer" });
		expect(bearer.json.cnf).toBeUndefined();
	});

	it("answers inactive for tokens the caller may not see, broken tokens and nothing more [rfc7662-2.2-b] [rfc7662-2.2-c] [rfc7662-4-f] [rfc7662-5-a]", async () => {
		const s = await serve();
		const token = await s.issue();
		const inactive = { active: false };
		const answer = async (as: string, sent: string) => (await s.post(as, { token: sent })).json;
		expect(await answer("other", token), "an audience the caller may not see").toEqual(inactive);
		expect(await answer("api", `${token}x`), "a token altered").toEqual(inactive);
		expect(await answer("api", "garbage"), "no token at all").toEqual(inactive);
	});

	it("refuses public clients, missing tokens, repeated parameters and bad client credentials, recording only the credentials' refusal [rfc7662-2.1-a] [rfc7662-2.1-d]", async () => {
		const s = await serve();
		const token = await s.issue();
		expect((await s.post(undefined, { token, client_id: "pub" })).status).toBe(401);
		expect((await s.post("api", {})).error).toBe("invalid_request");
		for (const repeated of [
			[["token", token]],
			[
				["token_type_hint", "access_token"],
				["token_type_hint", "access_token"],
			],
		] as [string, string][][]) {
			const answer = await s.post("api", [["token", token], ...repeated]);
			expect([answer.status, answer.error]).toEqual([400, "invalid_request"]);
		}
		const wrong = { token, client_id: "api", client_secret: `${clientSecret("api")}x` };
		expect((await s.post(undefined, wrong)).status).toBe(401);
		expect(s.events).toEqual([
			{
				kind: "client.authentication.failure",
				at: expect.any(Number),
				attributes: { source: "127.0.0.1", reason: "bad_credentials" },
			},
		]);
	});

	it("answers 503 when a condition on access tokens cannot tell, never inactive, recording and warning so [rfc7662-4-a]", async () => {
		const down = unavailableSwitch<AccessCondition>();
		const condition = defineModule({ name: "condition", replicaSafe: false, takes: [] }, (m) => [
			m
				.contribute(accessConditions)
				.by(() => down.wrap({ name: "test", holds: async () => "holds" as const })),
		]);
		const s = await serve({ extra: [condition] });
		const token = await s.issue();
		expect(await s.active(token)).toBe(true);
		down.unavailable("holds");
		const answer = await s.post("app", { token });
		expect([answer.status, answer.error]).toEqual([503, "temporarily_unavailable"]);
		expect(s.events).toEqual([
			{
				kind: "introspection.unavailable",
				at: expect.any(Number),
				attributes: { source: "127.0.0.1" },
			},
		]);
		expect(s.warnings()).toEqual([
			["http.unavailable", { what: "test", route: "/oauth/introspect" }],
		]);
	});
});

it("lets no page through: introspection is between servers", async () => {
	const origin = "https://app.example";
	const { base } = await serve({ http: { "cors-origins": [origin] } });
	const asked = await fetch(`${base}/oauth/introspect`, {
		method: "OPTIONS",
		headers: { origin, "access-control-request-method": "POST" },
	});
	expect(asked.headers.get("access-control-allow-origin")).toBeNull();
});
