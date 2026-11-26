import { grants, sessionIssuances } from "@mod/grants";
import { defineModule, Unavailable } from "@mod/kernel";
import { type IssuanceRequest, issuancePolicies } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { answered } from "../../../test/deployment.ts";
import { echoClients, serve } from "../../../test/served.ts";

describe("token endpoint", () => {
	it("refuses a second bundle from one request as the grant's fault, answering none of it", async () => {
		const twice = defineModule({ name: "twice", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async (input) => {
					await answered(input, {});
					return answered(input, { second: true });
				},
			})),
		]);
		const post = await serve([twice], { clients: [echoClients.echo()] });
		const answer = await post({ grant_type: "urn:test:echo" }, "echo");
		expect(answer.status).toBe(500);
		expect(answer.body).not.toHaveProperty("second");
	});

	it("issues for the lifetime a grant gives in place of tokens' own", async () => {
		const longer = defineModule({ name: "longer", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, issue }) => {
					const grant = {
						subject: "s",
						subjectKind: "user" as const,
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
					};
					const issued = await issue({ access: grant }, { lifetimeSeconds: 7200 });
					if (issued.kind === "refused") return issued;
					return { kind: "issued", body: { expires_in: issued.access.expiresIn } };
				},
			})),
		]);
		const post = await serve([longer], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body).toEqual({
			expires_in: 7200,
		});
	});

	it("tells each session issuance of a token issued from a session before the grant answers, and one that fails answers no token", async () => {
		const told: unknown[] = [];
		const echo = defineModule({ name: "echo", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, issue }) => {
					const session = param("session");
					const grant = {
						subject: "s",
						subjectKind: "user" as const,
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
					};
					const issued = await issue({ access: grant }, session === undefined ? {} : { session });
					if (issued.kind === "refused") return issued;
					told.push("answered");
					return { kind: "issued", body: { id: issued.access.id } };
				},
			})),
			...["first", "second"].map((name) =>
				m.contribute(sessionIssuances).by(() => ({
					issued: async (session, access) => {
						if (session === "failing") throw new Unavailable("test");
						told.push({ name, session, access });
					},
				})),
			),
		]);
		const post = await serve([echo], { clients: [echoClients.echo()] });
		const { id } = (await post({ grant_type: "urn:test:echo", session: "sid" }, "echo")).body;
		const access = { id, expiresAt: 1_800_000_300_000 };
		expect(told).toEqual([
			{ name: "first", session: "sid", access },
			{ name: "second", session: "sid", access },
			"answered",
		]);
		told.length = 0;
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		expect(told).toEqual(["answered"]);
		told.length = 0;
		const failed = await post({ grant_type: "urn:test:echo", session: "failing" }, "echo");
		expect([failed.status, failed.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(told).toEqual([]);
	});

	it("issues client credentials through the issuance policies", async () => {
		const asked: IssuanceRequest[] = [];
		const refusing = defineModule({ name: "refusing", replicaSafe: false, takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return { kind: "refused", reason: "test_reason", description: "not for clients" };
				},
			})),
		]);
		const post = await serve([refusing]);
		const refused = await post({ grant_type: "client_credentials" }, "basic");
		expect([refused.status, refused.body]).toEqual([
			400,
			{ error: "invalid_grant", error_description: "not for clients" },
		]);
		expect(asked).toEqual([
			{
				grant: {
					subject: "basic",
					subjectKind: "user",
					issuedTo: "basic",
					audience: ["https://api"],
					scope: ["read"],
				},
				grantType: "client_credentials",
			},
		]);
	});
});
