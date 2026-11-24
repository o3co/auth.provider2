import type { Client, Section } from "@mod/clients";
import type { GrantInput } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import type { RateLimit } from "@mod/rate-limit";
import { describe, expect, it } from "vitest";
import { clientCredentials, clientCredentialsGrantType } from "../src/contract.ts";

const issuer = "https://as.example";
const api = "https://api.example";

/**
 * A confidential client of a version its publisher signed, its own ceiling `self` (one entry, `read`
 * at `api`, unless given) and its person's delegation `delegated` under client-allowance's section.
 */
const client = (
	parts: { kind?: Client["kind"]; signed?: boolean; self?: unknown[]; id?: string } = {},
	delegated: Record<string, unknown> = {},
): Client => ({
	id: parts.id ?? "svc",
	kind: parts.kind ?? "confidential",
	method: "private_key_jwt",
	registered: false,
	version: 4,
	...(parts.signed === false ? {} : { signed: true as const }),
	section: <T>(section: Section<T>) =>
		(section.name === "client-allowance"
			? {
					grants: [clientCredentialsGrantType],
					scopes: [],
					audiences: [],
					self: parts.self ?? [{ audience: api, scopes: ["read"] }],
					...delegated,
				}
			: {}) as T,
});

/** The key the test client's assertion was verified with, written in its record, for it alone. */
const held = "held-key";
const proved = { assertion: true };
/** An assertion verified by a key fetched from the client's jwks-uri. */
const fetched = { assertion: "fetched" };
const keys = {
	verifiedOf: (proof: unknown, of?: Client) => {
		if (of?.id !== "svc") return undefined;
		const verified = { client: "svc", key: { kty: "EC" }, thumbprint: held, version: 4 };
		if (proof === proved) return { ...verified, written: true as const };
		return proof === fetched ? verified : undefined;
	},
};
const dpop = (confirmation: string) => ({ member: "jkt", confirmation, tokenType: "DPoP" });

/** Counts each request, answering `limited` where asked. */
const counter = (limited = false) => {
	const counted: unknown[] = [];
	const counting: Pick<RateLimit, "hit"> = {
		hit: async (name, key, window) => {
			counted.push({ name, key, window });
			return limited ? { kind: "limited", retryAfterMs: 1500 } : { kind: "allowed" };
		},
	};
	return { counted, counting };
};

/** The grant asked with these parameters, a DPoP binding by the held key and the assertion unless given. */
async function ask(
	c: Client,
	params: Record<string, string> = { scope: "read" },
	options: {
		refused?: boolean;
		binding?: { member: string; confirmation: string; tokenType: string } | null;
		authenticated?: unknown;
		counting?: Pick<RateLimit, "hit">;
		suspended?: readonly string[];
		target?: (audience: readonly string[]) => unknown;
	} = {},
) {
	const issued: unknown[] = [];
	const binding = options.binding === undefined ? dpop(held) : options.binding;
	const input = {
		client: c,
		authenticated: "authenticated" in options ? options.authenticated : proved,
		...(binding ? { binding } : {}),
		param: (name: string) => params[name],
		target:
			options.target ??
			((audience: readonly string[]) => ({ kind: "audience" as const, audience })),
		issue: async (bundle: unknown, from: unknown) => {
			issued.push({ bundle, from });
			return options.refused
				? { kind: "refused" as const, policy: "p", description: "no" }
				: {
						kind: "issued" as const,
						access: { token: "t", tokenType: "DPoP", expiresIn: 300 },
					};
		},
	} as unknown as GrantInput;
	const limits = {
		counting: options.counting ?? counter().counting,
		requests: 60,
		suspended: options.suspended ?? [],
	};
	return { answer: await clientCredentials(issuer, keys, limits).handle(input), issued };
}

describe("client credentials", () => {
	it("is client_credentials, for the client's own subject, reading no ambient credential and taking its audience from the request", () => {
		const grant = clientCredentials(issuer, keys, {
			counting: counter().counting,
			requests: 60,
			suspended: [],
		});
		expect([grant.grantType, grant.readsAmbient, grant.targets, grant.subjectKind]).toEqual([
			"client_credentials",
			"none",
			true,
			"client",
		]);
	});

	it("issues a client of a signed version a token for itself, within its own ceiling, for five minutes [rfc6749-4.4.3-a] [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-3.3-a]", async () => {
		const { answer, issued } = await ask(client());
		expect(answer).toEqual({
			kind: "issued",
			body: { access_token: "t", token_type: "DPoP", expires_in: 300, scope: "read" },
		});
		// One bundle, its access token's subject the client itself, of the kind `client`; no root on the log.
		expect(issued).toEqual([
			{
				bundle: {
					access: {
						subject: "svc",
						subjectKind: "client",
						issuedTo: "svc",
						audience: [api],
						scope: ["read"],
					},
				},
				from: { lifetimeSeconds: 300 },
			},
		]);
	});

	it("asks the audience rule within the client's own audiences, naming none by default", async () => {
		const asked: unknown[] = [];
		const target = (audience: readonly string[], within: (a: string) => boolean) => {
			asked.push([audience, within(api), within("https://elsewhere")]);
			return { kind: "error", error: "invalid_target", description: "no" };
		};
		const { answer, issued } = await ask(client(), { scope: "read" }, { target } as never);
		expect([answer, issued, asked]).toEqual([
			{ kind: "error", error: "invalid_target", description: "no" },
			[],
			[[[], true, false]],
		]);
	});

	it("never passes over a resource asked that no rule read: it must be the one entry's audience", async () => {
		expect((await ask(client(), { scope: "read", resource: api })).answer).toMatchObject({
			kind: "issued",
		});
		const elsewhere = await ask(client(), { scope: "read", resource: "https://elsewhere" });
		expect([elsewhere.answer, elsewhere.issued]).toEqual([
			{
				kind: "error",
				error: "invalid_target",
				description: "the resource asked is not the audience given",
			},
			[],
		]);
	});

	it("refuses a public client, however it authenticated, and a suspended one [rfc6749-4.4-a] [rfc6749-2.3-a]", async () => {
		expect((await ask(client({ kind: "public" }))).answer).toEqual({
			kind: "error",
			error: "unauthorized_client",
		});
		const { counted, counting } = counter();
		expect((await ask(client(), undefined, { suspended: ["svc"], counting })).answer).toEqual({
			kind: "error",
			error: "unauthorized_client",
			description: "the client is suspended",
		});
		expect(counted).toEqual([]);
	});

	it("issues by the client's own ceiling alone, never its person's delegation, the scope named", async () => {
		const delegated = client({ self: [] }, { scopes: ["read"], "default-scopes": ["read"] });
		expect((await ask(delegated)).answer).toMatchObject({ kind: "error", error: "invalid_target" });
		expect((await ask(client(), {})).answer).toEqual({
			kind: "error",
			error: "invalid_scope",
			description: "scope is required",
		});
		const outside = await ask(client(), { scope: "write" });
		expect([outside.answer, outside.issued]).toEqual([
			{ kind: "error", error: "invalid_scope" },
			[],
		]);
		expect((await ask(client({ signed: false }))).answer).toMatchObject({
			kind: "error",
			error: "unauthorized_client",
		});
	});

	it("answers a refused issuance as the policies refused it", async () => {
		const { answer } = await ask(client(), undefined, { refused: true });
		expect(answer).toMatchObject({ kind: "refused", policy: "p" });
	});
});

describe("the client's key", () => {
	const unwritten = {
		kind: "error",
		error: "unauthorized_client",
		description:
			"the client authenticates by private_key_jwt under a key written in its record alone",
	};

	it("is a key written in the client's record that verified its assertion", async () => {
		// A secret's authentication verifies no key; a key at the client's jwks-uri is not written.
		for (const authenticated of [undefined, null, fetched, { assertion: true }]) {
			const { answer, issued } = await ask(client(), undefined, { authenticated });
			expect([answer, issued], String(authenticated)).toEqual([unwritten, []]);
		}
		// Another client's genuine verification reads as none for this one.
		expect((await ask(client({ id: "other" }))).answer).toEqual(unwritten);
	});
});

describe("a token bound by DPoP", () => {
	it("is issued only where the proof's key is the key the client's assertion was verified with", async () => {
		expect((await ask(client())).answer).toMatchObject({ kind: "issued" });
		expect(await ask(client(), undefined, { binding: dpop("another-key") })).toEqual({
			answer: {
				kind: "error",
				error: "invalid_dpop_proof",
				description: "the proof's key is not the key the client's assertion was verified with",
			},
			issued: [],
		});
	});

	it("is required: a request bound by none, or by another kind, is refused", async () => {
		expect(await ask(client(), undefined, { binding: null })).toEqual({
			answer: {
				kind: "error",
				error: "invalid_request",
				description: "a DPoP proof by the client's key is required",
			},
			issued: [],
		});
		const other = { member: "x5t#S256", confirmation: held, tokenType: "Bearer" };
		expect((await ask(client(), undefined, { binding: other })).answer).toEqual({
			kind: "error",
			error: "unauthorized_client",
			description: "the client's token is bound by DPoP alone",
		});
	});
});

describe("how often a client is issued", () => {
	it("counts each request of a client once it is authenticated, by its id, sixty a minute by default", async () => {
		const { counted, counting } = counter();
		await ask(client(), undefined, { counting });
		expect(counted).toEqual([
			{ name: "client-credentials", key: "svc", window: { limit: 60, ms: 60_000 } },
		]);
	});

	it("answers too many requests with the wait, issuing nothing", async () => {
		const { answer, issued } = await ask(client(), undefined, { counting: counter(true).counting });
		expect([answer, issued]).toEqual([
			{ kind: "error", error: "rate_limited", status: 429, retryAfterMs: 1500 },
			[],
		]);
	});

	it("is unavailable when it cannot count, never letting a request through uncounted", async () => {
		const counting = {
			hit: async () => {
				throw new Unavailable("rate-limit");
			},
		};
		await expect(ask(client(), undefined, { counting })).rejects.toBeInstanceOf(Unavailable);
	});
});
