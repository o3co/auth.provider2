import type { Client } from "@mod/clients";
import { overHttp } from "@mod/front-core-wire";
import type { HttpRequest } from "@mod/http";
import { typs } from "@mod/sdk-core-wire";
import type { BindingOutcome, SenderBindings } from "@mod/sender-binding";
import { describe, expect, it } from "vitest";
import type { PushedRequests, StoredPush } from "../src/contract.ts";
import { parPath, pushedSource, pushing, requestUriPrefix } from "../src/push/push.ts";

const now = 1_800_000_000_000;
const issuer = "https://issuer.example";
const client = {
	id: "c1",
	kind: "confidential",
	method: "private_key_jwt",
	registered: true,
} as Client;

const claims = (more: Record<string, unknown> = {}) => ({
	iss: "c1",
	client_id: "c1",
	aud: issuer,
	jti: "j1",
	exp: now / 1000 + 60,
	dpop_jkt: "jkt-1",
	...more,
});
const jar = (payload: Record<string, unknown>, by = "c1") =>
	`h.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${by}`;

function memoryPushed() {
	const kept = new Map<string, { value: StoredPush; until: number }>();
	const pushed: PushedRequests = {
		async create(key, record, lifetimeMs) {
			if (kept.has(key)) return "exists";
			kept.set(key, { value: record, until: now + lifetimeMs });
			return "created";
		},
		read: async (key) => kept.get(key)?.value,
	};
	return { pushed, kept };
}

function harness(
	p: {
		proved?: BindingOutcome;
		authenticated?: boolean;
		/** How long checking the proof takes, in ms; none unless told. */
		proofMs?: number;
	} = {},
) {
	const store = memoryPushed();
	let n = 0;
	let clock = now;
	const bindings: Pick<SenderBindings, "bindingOf" | "requestedOf"> = {
		bindingOf: async () => {
			clock += p.proofMs ?? 0;
			return p.proved ?? { kind: "none" };
		},
		requestedOf: (param) => {
			const jkt = param("dpop_jkt");
			if (jkt === "bad") return { kind: "malformed", parameter: "dpop_jkt" };
			return jkt === undefined
				? { kind: "none" }
				: { kind: "requested", binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" } };
		},
	};
	const push = pushing({
		clients: {
			authenticate: async () =>
				p.authenticated === false
					? { kind: "refused", reason: "bad_credentials", challenges: [] }
					: { kind: "authenticated", client, challenges: [] },
		} as never,
		assertion: {
			verifySignedBy: async (c, jwt, typ) => {
				const [, payload, by] = jwt.split(".");
				if (typ !== typs.jar || by !== c.id) return { kind: "refused", reason: "signature" };
				return {
					kind: "signed",
					claims: JSON.parse(Buffer.from(payload ?? "", "base64url").toString()),
				};
			},
		},
		bindings,
		pushed: store.pushed,
		issuer,
		maxLifetimeS: 90,
		skewS: 30,
		now: () => clock,
		token: () => {
			n += 1;
			return `t${n}`;
		},
	});
	const send = async (form: Record<string, string>) => {
		const fields = new Map(Object.entries(form).map(([k, v]) => [k, [v]]));
		const request = {
			fields: { single: (name: string) => fields.get(name)?.[0] },
		} as unknown as HttpRequest;
		const r = await push(request);
		return {
			status: r.status,
			json: (r.body as { json: Record<string, unknown> }).json,
			headers: r.headers ?? {},
		};
	};
	return { send, store };
}

describe("a pushed authorization request", () => {
	it("keeps the client's JAR under a fresh request_uri, for its JAR's life", async () => {
		const h = harness();
		const r = await h.send({ request: jar(claims()) });
		expect(r).toMatchObject({
			status: 201,
			json: { request_uri: `${requestUriPrefix}t1`, expires_in: 60 },
		});
		expect(h.store.kept.get(`${requestUriPrefix}t1`)?.until).toBe(now + 90_000);
	});

	it("refuses an unauthenticated client, another client's JAR, and a JAR not for this issuer", async () => {
		expect(await harness({ authenticated: false }).send({ request: jar(claims()) })).toMatchObject({
			status: 401,
			json: { error: "invalid_client" },
		});
		const h = harness();
		expect(await h.send({ request: jar(claims(), "c2") })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims({ iss: "c2" })) })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims({ aud: "https://other.example" })) })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.send({ request: jar(claims()), client_id: "c2" })).toMatchObject({
			json: { error: "invalid_request" },
		});
	});

	it("refuses a JAR expired, living too long, or naming no jti or dpop_jkt", async () => {
		const h = harness();
		for (const more of [
			{ exp: now / 1000 },
			{ exp: now / 1000 + 91 },
			{ jti: undefined },
			{ dpop_jkt: undefined },
		])
			expect(await h.send({ request: jar(claims(more)) })).toMatchObject({
				status: 400,
				json: { error: "invalid_request_object" },
			});
		expect(h.store.kept.size).toBe(0);
	});

	it("takes a DPoP proof of the key the JAR names, and refuses one of another (A44)", async () => {
		const proof = (confirmation: string): BindingOutcome => ({
			kind: "bound",
			binding: { member: "jkt", confirmation, tokenType: "DPoP" },
		});
		expect(
			await harness({ proved: proof("jkt-1") }).send({ request: jar(claims()) }),
		).toMatchObject({ status: 201 });
		expect(
			await harness({ proved: proof("jkt-2") }).send({ request: jar(claims()) }),
		).toMatchObject({
			status: 400,
			json: { error: "invalid_dpop_proof" },
		});
		const refusedProof: BindingOutcome = {
			kind: "refused",
			error: "invalid_dpop_proof",
			description: "bad",
		};
		expect(await harness({ proved: refusedProof }).send({ request: jar(claims()) })).toMatchObject({
			json: { error: "invalid_dpop_proof" },
		});
	});

	it("gives back the binding kind's headers with its refusal, so a client may take the nonce asked", async () => {
		const nonce: BindingOutcome = {
			kind: "refused",
			error: "use_dpop_nonce",
			description: "a nonce is asked",
			headers: { "dpop-nonce": "n1" },
		};
		const r = await harness({ proved: nonce }).send({ request: jar(claims()) });
		expect(r).toMatchObject({ status: 400, json: { error: "use_dpop_nonce" } });
		expect(r.headers).toMatchObject({ "dpop-nonce": "n1" });
	});

	it("refuses a dpop_jkt out of its form and two bindings, is unavailable where the kind cannot tell, and takes another kind's binding", async () => {
		expect(await harness().send({ request: jar(claims({ dpop_jkt: "bad" })) })).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(
			await harness({ proved: { kind: "multiple_bindings" } }).send({ request: jar(claims()) }),
		).toMatchObject({
			json: { error: "invalid_request" },
		});
		const unknown: BindingOutcome = { kind: "refused", error: "x", unavailable: true };
		await expect(harness({ proved: unknown }).send({ request: jar(claims()) })).rejects.toThrow();
		const ambient: BindingOutcome = {
			kind: "bound",
			binding: { member: "x5t#S256", confirmation: "c", tokenType: "Bearer" },
		};
		expect(await harness({ proved: ambient }).send({ request: jar(claims()) })).toMatchObject({
			status: 201,
		});
	});

	it("refuses a request_uri and authorization_details sent with the push (RFC 9126 §2.1)", async () => {
		const h = harness();
		expect(await h.send({ request: jar(claims()), request_uri: "other" })).toMatchObject({
			json: { error: "invalid_request" },
		});
		expect(await h.send({ request: jar(claims()), authorization_details: "other" })).toMatchObject({
			json: { error: "invalid_request" },
		});
	});

	it("serves the path the wire's par operation names", () => {
		expect(parPath).toBe(overHttp.operations.par.path);
	});
});

describe("the login's start by request_uri", () => {
	it("gives the pushing client its JAR, and refuses another client, an unknown or no such uri", async () => {
		const h = harness();
		const request = jar(claims());
		await h.send({ request });
		const source = pushedSource(h.store.pushed);
		const uri = `${requestUriPrefix}t1`;
		expect(await source.jarOf({ requestUri: uri }, client)).toEqual({ jar: request });
		expect(await source.jarOf({ requestUri: uri }, { ...client, id: "c2" })).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ requestUri: `${requestUriPrefix}none` }, client)).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ requestUri: "https://elsewhere" }, client)).toMatchObject({
			refused: { error: "invalid_request_uri" },
		});
		expect(await source.jarOf({ request }, client)).toBeUndefined();
	});

	it("refuses, keeping nothing, a JAR that expired while its proof was checked", async () => {
		const h = harness({ proofMs: 61_000 });
		expect(await h.send({ request: jar(claims()) })).toMatchObject({
			status: 400,
			json: { error: "invalid_request_object", error_description: "the request has expired" },
		});
		expect(h.store.kept.size).toBe(0);
	});
});
