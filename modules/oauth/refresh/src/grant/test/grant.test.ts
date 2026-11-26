import type { Client } from "@mod/clients";
import type { BundleRequest, GrantInput } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import { referenceOf } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import {
	binding,
	jws,
	lifetimeMs,
	now,
	recordsAt,
	statement,
	statementPayload,
} from "../../../test/fixtures.ts";
import { type FamilyRecord, nameOf, read, sha256, tokenOf, write } from "../../record.ts";
import { type GrantParts, refreshGrant, revocableFamilies } from "../grant.ts";

const secret = "s".repeat(43);
const token = tokenOf("r-bundle", secret);
const iat = now / 1000 - 10;
const client = { id: "app" } as Client;

const family: FamilyRecord = {
	format: 1,
	subject: "alice",
	client: "app",
	session: "sess-1",
	scope: ["read", "write"],
	audience: ["https://api"],
	amr: ["pop", "user"],
	authTime: now - 5_000,
	end: iat * 1000 + lifetimeMs,
	binding,
	statement,
	assertion: "{}",
	credential: "cred-1",
	registration: "r-key",
	publicKey: "pk",
	generation: 4,
	secret: sha256(secret),
	code: "code-digest",
};

/** The grant over a family kept as given, its root as the keys and webauthn answer it. */
async function world(over: Partial<GrantParts> = {}, kept: FamilyRecord = family) {
	const records = recordsAt();
	await records.records.create(nameOf.family("r-bundle"), write.family(kept), lifetimeMs, "alice");
	const refreshed: unknown[][] = [];
	const revoked: string[] = [];
	const parts: GrantParts = {
		records: records.records,
		keys: {
			verifyOf: async (generation, jws) =>
				generation === 4 && jws === statement
					? { kind: "valid", claims: statementPayload(iat) }
					: { kind: "invalid", reason: "signature" },
		},
		ceremonies: {
			reverifyAssertion: (assertion, key) =>
				assertion === "{}" && key === "pk" ? { credential: "cred-1" } : undefined,
		},
		sessions: { entryOf: async () => ({ kind: "entered", endsAt: now + 3_600_000 }) as never },
		tokens: {
			revokeReferenced: async (reference) => {
				revoked.push(reference);
				return { kind: "revoked" };
			},
		},
		selections: {
			forRefreshed: async (...args) => {
				refreshed.push(args);
			},
		},
		lifetimeMs,
		now: records.now,
		...over,
	};
	return {
		records,
		refreshed,
		revoked,
		grant: refreshGrant(parts),
		revocable: revocableFamilies(parts),
	};
}

/** A request's input, as the token endpoint hands it on, recording the bundle it asks. */
function input(params: Record<string, string>, over: Partial<GrantInput> = {}) {
	const asked: { bundle: BundleRequest; from: unknown }[] = [];
	const given: GrantInput = {
		request: {} as never,
		client,
		param: (name) => params[name],
		value: (name) => params[name],
		target: (audience) => ({ kind: "audience", audience }),
		binding,
		admits: async () => ({ kind: "allowed" }),
		issue: async (bundle, from) => {
			asked.push({ bundle, from });
			return {
				kind: "issued",
				access: {
					token: "at",
					id: "tok-1",
					expiresAt: now + 300_000,
					expiresIn: 300,
					tokenType: "DPoP",
				},
			};
		},
		...over,
	};
	return { given, asked };
}

const refused = { kind: "error", error: "invalid_grant", description: "invalid refresh token" };

/** A session entered when first read, and no longer when read again after issuing. */
const afterIssuing = () => {
	let reads = 0;
	return async () =>
		reads++ === 0
			? ({ kind: "entered", endsAt: now + 3_600_000 } as never)
			: ({ kind: "absent" } as const);
};

describe("a refresh of a rooted family", () => {
	it("issues one bundle rooted in the family, answering its one refresh token again, never rotated", async () => {
		const w = await world();
		const { given, asked } = input({ refresh_token: token });
		expect(await w.grant.handle(given)).toEqual({
			kind: "issued",
			body: {
				access_token: "at",
				token_type: "DPoP",
				expires_in: 300,
				scope: "read write",
				refresh_token: token,
			},
		});
		expect(asked).toEqual([
			{
				bundle: {
					root: "r-bundle",
					via: { via: "refresh" },
					access: {
						subject: "alice",
						subjectKind: "user",
						issuedTo: "app",
						audience: ["https://api"],
						scope: ["read", "write"],
						amr: ["pop", "user"],
						authenticatedAt: now - 5_000,
					},
				},
				from: { session: "sess-1", continuing: true, notAfter: now + 3_600_000 },
			},
		]);
		expect(w.refreshed).toEqual([
			["r-bundle", client, "alice", { id: "tok-1", expiresAt: now + 300_000 }],
		]);
		expect(w.revoked).toEqual([]);
	});

	it("revokes the token it issued where its session closed while it was issued and recorded, and answers none (proposal 3.15, 1)", async () => {
		// The session enters when first read, and is closed when read again after issuing.
		const entryOf = afterIssuing();
		const w = await world({ sessions: { entryOf } });
		const { given, asked } = input({ refresh_token: token });
		expect(await w.grant.handle(given)).toEqual(refused);
		expect(asked).toHaveLength(1);
		expect(w.revoked).toEqual([referenceOf({ id: "tok-1", expiresAt: now + 300_000 })]);
		expect(w.refreshed).toEqual([]);
	});

	it("fails as unavailable where the token issued while its session closed cannot be revoked", async () => {
		const entryOf = afterIssuing();
		const w = await world({
			sessions: { entryOf },
			tokens: { revokeReferenced: async () => ({ kind: "unsupported" }) },
		});
		await expect(w.grant.handle(input({ refresh_token: token }).given)).rejects.toBeInstanceOf(
			Unavailable,
		);
		expect(w.refreshed).toEqual([]);
		// The denylist's store failing: the failure goes on, and no token is answered either.
		const failing = await world({
			sessions: { entryOf: afterIssuing() },
			tokens: {
				revokeReferenced: async () => {
					throw new Unavailable("token-denylist");
				},
			},
		});
		await expect(
			failing.grant.handle(input({ refresh_token: token }).given),
		).rejects.toBeInstanceOf(Unavailable);
		expect(failing.refreshed).toEqual([]);
	});

	it("narrows the scope within the family's, each word once, never to offline_access alone", async () => {
		const w = await world();
		const scoped = async (scope: string) =>
			w.grant.handle(input({ refresh_token: token, scope }).given);
		expect(await scoped("read")).toMatchObject({ body: { scope: "read" } });
		expect(await scoped("read offline_access")).toMatchObject({ body: { scope: "read" } });
		for (const scope of ["admin", "read read", "offline_access", "read  write"])
			expect(await scoped(scope), scope).toMatchObject({ kind: "error", error: "invalid_scope" });
	});

	it("refuses alike a token of no family, another secret, another client, or no proof by the family's key", async () => {
		const w = await world();
		const handled = (params: Record<string, string>, over: Partial<GrantInput> = {}) =>
			w.grant.handle(input(params, over).given);
		expect(await handled({})).toMatchObject({ error: "invalid_request" });
		for (const t of [
			"x",
			tokenOf("r-none", secret),
			tokenOf("r-bundle", "w".repeat(43)),
			`${token}.more`,
		])
			expect(await handled({ refresh_token: t }), t).toEqual(refused);
		expect(await handled({ refresh_token: token }, { client: { id: "other" } as Client })).toEqual(
			refused,
		);
		const other = { ...binding, confirmation: "other-key" };
		expect(await handled({ refresh_token: token }, { binding: other })).toEqual(refused);
		const { binding: _, ...unbound } = input({ refresh_token: token }).given;
		expect(await w.grant.handle(unbound)).toEqual(refused);
	});

	it("refuses a family revoked, past its end, or whose session no longer enters", async () => {
		const revoked = await world({}, { ...family, revoked: true });
		expect(await revoked.grant.handle(input({ refresh_token: token }).given)).toEqual(refused);
		const ended = await world();
		ended.records.move(family.end - now);
		expect(await ended.grant.handle(input({ refresh_token: token }).given)).toEqual(refused);
		const closed = await world({
			sessions: { entryOf: async () => ({ kind: "absent" }) },
		});
		expect(await closed.grant.handle(input({ refresh_token: token }).given)).toEqual(refused);
	});

	it("checks its root again: the statement by its generation's ring, of the client and key, the assertion by the key recorded", async () => {
		const at = async (over: Partial<GrantParts>, kept = family) =>
			(await world(over, kept)).grant.handle(input({ refresh_token: token }).given);
		expect(await at({}, { ...family, generation: 3 })).toEqual(refused);
		const other = (claims: Readonly<Record<string, unknown>>) => ({
			verifyOf: async () => ({ kind: "valid" as const, claims }),
		});
		expect(await at({ keys: other(statementPayload(iat, { client_id: "another" })) })).toEqual(
			refused,
		);
		expect(await at({ keys: other(statementPayload(iat, { dpop_jkt: "another" })) })).toEqual(
			refused,
		);
		expect(await at({ keys: other(statementPayload(iat, { scope: "read" })) })).toEqual(refused);
		expect(await at({ keys: other({ not: "a statement" }) })).toEqual(refused);
		// Its end within its statement's issue and the delegation's length.
		expect(await at({}, { ...family, end: iat * 1000 + lifetimeMs + 1 })).toEqual(refused);
		// The resource its statement asked is the family's one audience.
		const resource = other(statementPayload(iat, { resource: "https://api" }));
		expect(await at({ keys: resource })).toMatchObject({ kind: "issued" });
		expect(await at({ keys: resource }, { ...family, audience: ["https://other"] })).toEqual(
			refused,
		);
		expect(
			await at({ keys: resource }, { ...family, audience: ["https://api", "https://other"] }),
		).toEqual(refused);
		expect(await at({ ceremonies: { reverifyAssertion: () => undefined } })).toEqual(refused);
		expect(
			await at({ ceremonies: { reverifyAssertion: () => ({ credential: "cred-2" }) } }),
		).toEqual(refused);
		expect(jws(statementPayload())).toBe(statement);
	});

	it("refuses a family whose scope is offline_access alone, asked or not", async () => {
		const asked = statementPayload(iat, { scope: "offline_access" });
		const keys = { verifyOf: async () => ({ kind: "valid" as const, claims: asked }) };
		const w = await world({ keys }, { ...family, scope: ["offline_access"] });
		expect(await w.grant.handle(input({ refresh_token: token }).given)).toMatchObject({
			error: "invalid_scope",
		});
	});

	it("answers a family the flow's state no longer holds as every refused token", async () => {
		const w = await world();
		const ended = {
			kind: "refused",
			refusal: {
				kind: "refused",
				policy: "token-endpoint",
				reason: "family",
				description: "the family has ended",
			},
		} as const;
		expect(
			await w.grant.handle(input({ refresh_token: token }, { issue: async () => ended }).given),
		).toEqual(refused);
	});

	it("passes a policy's refusal and the token endpoint's on unread, keeping nothing for a token never issued", async () => {
		const w = await world();
		const no = {
			kind: "refused",
			refusal: { kind: "refused", policy: "p", reason: "r", description: "d" },
		} as const;
		expect(
			await w.grant.handle(input({ refresh_token: token }, { admits: async () => no }).given),
		).toEqual(no);
		expect(
			await w.grant.handle(input({ refresh_token: token }, { issue: async () => no }).given),
		).toEqual(no);
		expect(w.refreshed).toEqual([]);
	});
});

describe("revoking a refresh token", () => {
	it("revokes its family for its own client, answering another client's done and an unknown token unknown", async () => {
		const w = await world();
		expect(await w.revocable.revoke(token, { id: "other" } as Client)).toBe("done");
		expect(await w.revocable.revoke(tokenOf("r-bundle", "w".repeat(43)), client)).toBe("unknown");
		expect(await w.revocable.revoke("x", client)).toBe("unknown");
		expect(await w.revocable.revoke(token, client)).toBe("written");
		expect(read.family(await w.records.records.read(nameOf.family("r-bundle")))?.revoked).toBe(
			true,
		);
		expect(await w.grant.handle(input({ refresh_token: token }).given)).toEqual(refused);
	});
});
