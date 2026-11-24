import type { Client, Section } from "@mod/clients";
import type { GrantInput } from "@mod/grants";
import { describe, expect, it } from "vitest";
import { clientCredentials, clientCredentialsGrantType } from "../src/contract.ts";

const issuer = "https://as.example";

/** A client of the kind given, allowed as `allowed` says under client-allowance's section. */
const client = (kind: Client["kind"], allowed: Record<string, unknown> = {}): Client => ({
	id: "svc",
	kind,
	method: kind === "public" ? "none" : "client_secret_basic",
	registered: true,
	section: <T>(section: Section<T>) =>
		(section.name === "client-allowance"
			? { grants: [clientCredentialsGrantType], scopes: [], audiences: [], ...allowed }
			: {}) as T,
});

/** The key the test client's assertion was verified with, as client-assertion reads it from the proof. */
const held = "held-key";
const proved = { assertion: true };
const keys = {
	verifiedOf: (proof: unknown) =>
		proof === proved
			? { client: "svc", key: { kty: "EC" }, thumbprint: held, version: 4 }
			: undefined,
};

/** The grant asked with these parameters and binding, issuing what it is given unless the policies refuse. */
async function ask(
	c: Client,
	params: Record<string, string> = {},
	refused = false,
	binding?: { member: string; confirmation: string; tokenType: string },
	proof: unknown = proved,
) {
	const issued: unknown[] = [];
	const input = {
		client: c,
		proof,
		...(binding ? { binding } : {}),
		param: (name: string) => params[name],
		target: (audience: readonly string[]) => ({ kind: "ok" as const, audience }),
		issue: async (grant: unknown) => {
			issued.push(grant);
			return refused
				? { kind: "refused" as const, policy: "p", description: "no" }
				: {
						kind: "issued" as const,
						access: { token: "t", tokenType: "Bearer", expiresIn: 300 },
					};
		},
	} as unknown as GrantInput;
	return { answer: await clientCredentials(issuer, keys).handle(input), issued };
}

describe("client credentials", () => {
	it("is client_credentials, reading no ambient credential and taking its audience from the request", () => {
		const grant = clientCredentials(issuer, keys);
		expect([grant.grantType, grant.readsAmbient, grant.targets]).toEqual([
			"client_credentials",
			"none",
			true,
		]);
	});

	it("issues a confidential client a token for itself, its default scope and the issuer as audience [rfc6749-4.4.3-a] [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-3.3-a]", async () => {
		const { answer, issued } = await ask(
			client("confidential", { scopes: ["read"], "default-scopes": ["read"] }),
		);
		expect(answer).toEqual({
			kind: "issued",
			body: { access_token: "t", token_type: "Bearer", expires_in: 300, scope: "read" },
		});
		// One bundle, its access token's subject the client itself, of the kind `client`; no root on the log.
		expect(issued).toEqual([
			{
				access: {
					subject: "svc",
					subjectKind: "client",
					issuedTo: "svc",
					audience: [issuer],
					scope: ["read"],
				},
			},
		]);
	});

	it("refuses a public client, however it authenticated, and a scope outside the allowance, before issuing [rfc6749-4.4-a] [rfc6749-2.3-a]", async () => {
		expect((await ask(client("public"))).answer).toEqual({
			kind: "error",
			error: "unauthorized_client",
		});
		// Its registered type decides, never the method it authenticated by.
		const withSecret = { ...client("public"), method: "client_secret_basic" } as Client;
		expect((await ask(withSecret)).answer).toEqual({ kind: "error", error: "unauthorized_client" });
		const outside = await ask(client("confidential", { scopes: ["read"] }), { scope: "write" });
		expect([outside.answer, outside.issued]).toEqual([
			{ kind: "error", error: "invalid_scope" },
			[],
		]);
	});

	it("answers a refused issuance as the policies refused it", async () => {
		const { answer } = await ask(
			client("confidential", { scopes: ["read"], "default-scopes": ["read"] }),
			{},
			true,
		);
		expect(answer).toMatchObject({ kind: "refused", policy: "p" });
	});
});

describe("a token bound by DPoP", () => {
	const allowed = client("confidential", { scopes: ["read"], "default-scopes": ["read"] });
	const dpop = (confirmation: string) => ({ member: "jkt", confirmation, tokenType: "DPoP" });

	const refused = {
		answer: {
			kind: "error",
			error: "invalid_dpop_proof",
			description: "the proof's key is not the key the client's assertion was verified with",
		},
		issued: [],
	};

	it("is issued only where the proof's key is the key the client's assertion was verified with", async () => {
		const bound = await ask(allowed, {}, false, dpop(held));
		expect(bound.answer).toMatchObject({ kind: "issued" });
		expect(await ask(allowed, {}, false, dpop("another-key"))).toEqual(refused);
	});

	it("is refused for a client whose authentication verified no key, a secret's, or another method's proof", async () => {
		expect(await ask(allowed, {}, false, dpop(held), null)).toEqual(refused);
		expect(await ask(allowed, {}, false, dpop(held), { assertion: true })).toEqual(refused);
	});

	it("leaves a binding of another kind, and none, as they are", async () => {
		const other = { member: "x5t#S256", confirmation: "another-key", tokenType: "Bearer" };
		expect((await ask(allowed, {}, false, other)).answer).toMatchObject({ kind: "issued" });
		expect((await ask(allowed)).answer).toMatchObject({ kind: "issued" });
	});
});
