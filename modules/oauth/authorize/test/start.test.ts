import type { Approvals, IssueAsk } from "@mod/approvals";
import type { Client } from "@mod/clients";
import { requests } from "@mod/front-core-wire";
import { type TargetRule, targetRules } from "@mod/grants";
import { testRequest } from "@mod/http/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { redirects } from "@mod/redirect-uris";
import resourceIndicators from "@mod/resource-indicators/module";
import { payloads, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { codeNeedsOver } from "../src/code-needs/code-needs.ts";
import type { JarReservations, RequestSource, StoredReservation } from "../src/contract.ts";
import { reserving } from "../src/jar/jar.ts";
import {
	byValue,
	claimsUnread,
	filledItems,
	type StartParts,
	starting,
	tFits,
} from "../src/start/start.ts";

const now = 1_800_000_000_000;
const issuer = "https://issuer.example";
const b64 = (n: number, fill = 1) => Buffer.alloc(n, fill).toString("base64url");
const eEnc = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]).toString("base64url");

const client: Client = {
	id: "c1",
	kind: "public",
	method: "none",
	registered: true,
	section: <T>(s: { name: string }) =>
		(s.name === redirects.name
			? { "redirect-uris": ["https://rp.example/cb"] }
			: {
					grants: ["authorization_code"],
					scopes: ["read"],
					audiences: ["https://api.example"],
				}) as T,
};

const claims = (more: Record<string, unknown> = {}) => ({
	iss: "c1",
	aud: issuer,
	jti: "j1",
	exp: now / 1000 + 300,
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "read",
	nonce: "n",
	code_challenge: "c".repeat(43),
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	...more,
});
/** A JAR "signed" for the test: its payload in the middle, its signature its client's mark. */
const jar = (payload: Record<string, unknown>, by = "c1") =>
	`h.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${by}`;

function memoryReservations() {
	const kept = new Map<string, { value: StoredReservation; until: number }>();
	const reservations: JarReservations = {
		async create(key, record, lifetimeMs) {
			const live = kept.get(key);
			if (live && now < live.until) return "exists";
			kept.set(key, { value: structuredClone(record), until: now + lifetimeMs });
			return "created";
		},
		read: async (key) => structuredClone(kept.get(key)?.value),
		async change(key, change) {
			const entry = kept.get(key);
			if (!entry) return undefined;
			const next = change(structuredClone(entry.value));
			const before = entry.value;
			if (next) kept.set(key, { ...entry, value: structuredClone(next.value) });
			return { before, after: (kept.get(key) as { value: StoredReservation }).value };
		},
	};
	return reservations;
}

/** The n-th statement T and its challenge, as approvals answers them: a compact JWS, and 32 bytes in base64url. */
const statementOf = (n: number) => `aA.VCR7bn0.c2ln${n}`;
const challengeOf = (n: number) => Buffer.alloc(32, n).toString("base64url");

function harness(
	p: {
		allows?: boolean;
		/** Whether sign-up (F1) is composed; not unless told. */
		signUp?: boolean;
		refuse?: () => string | undefined;
		sources?: readonly RequestSource[];
		slow?: () => Promise<void>;
		/** Whether an ID token is made; made unless told otherwise. */
		idTokens?: boolean;
		/** The rule for the audience asked, as resource-indicators contributes it; none unless told. */
		rule?: Pick<TargetRule, "target">;
		/** The claims' reader; one that takes any unless told. */
		claims?: StartParts["claims"];
		/** The longest T asked; the route contract's unless told. */
		fits?: StartParts["fits"];
	} = {},
) {
	const asked: IssueAsk[] = [];
	const sought: string[] = [];
	let n = 0;
	let tokens = 0;
	let clock = now;
	const approvals: Pick<Approvals, "issue"> = {
		issue: async (ask) => {
			await p.slow?.();
			const reason = p.refuse?.();
			if (reason) return { kind: "refused", reason: reason as "limited" };
			asked.push(ask);
			n += 1;
			return {
				kind: "issued",
				statement: statementOf(n),
				hash: `h${n}`,
				challenge: challengeOf(n),
			};
		},
	};
	const start = starting({
		clients: {
			find: async (id) => {
				sought.push(id);
				return id === "c1" ? client : undefined;
			},
		},
		jar: {
			sources: p.sources ?? [byValue],
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
			issuer,
			maxLifetimeS: 600,
			now: () => clock,
		},
		reserve: reserving({
			reservations: memoryReservations(),
			skewS: 30,
			now: () => clock,
			token: () => {
				tokens += 1;
				return `t${tokens}`;
			},
		}),
		approvals,
		fits: p.fits ?? tFits,
		withoutPasskey: p.allows === undefined ? undefined : { allows: async () => p.allows === true },
		signUp: p.signUp ?? false,
		claims: p.claims ?? { refusal: () => undefined },
		needs: codeNeedsOver({
			idTokens: p.idTokens ?? true,
			targets: p.rule,
			issuer,
			bindings: {
				requestedOf: (param) => {
					const jkt = param("dpop_jkt");
					if (jkt === "bad") return { kind: "malformed", parameter: "dpop_jkt" };
					return jkt === undefined
						? { kind: "none" }
						: {
								kind: "requested",
								binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" },
							};
				},
			},
		}),
	});
	const send = (fields: Record<string, unknown>) =>
		start(testRequest({ json: fields, source: { address: "192.0.2.1" } }));
	const body = (fields: Record<string, unknown>) =>
		send(fields).then((r) => ({ status: r.status, json: (r.body as { json: unknown }).json }));
	const fields = (request: string, x = b64(32)) => ({
		clientId: "c1",
		request,
		eEnc,
		eSigX: x,
		eSigY: b64(32, 2),
	});
	const at = (t: number) => {
		clock = t;
	};
	return { asked, sought, body, fields, at };
}

describe("a login's start (②)", () => {
	it("issues T over the JAR's items and the screen's keys, and answers it with its challenge", async () => {
		const h = harness();
		const r = await h.body(h.fields(jar(claims())));
		expect(r).toEqual({
			status: 200,
			json: { statement: statementOf(1), challenge: challengeOf(1), create: false },
		});
		// The answer as the wire names ②'s (sdk-core-wire).
		expect(payloads.answers.authorization.safeParse(r.json).success).toBe(true);
		const [ask] = h.asked;
		expect(ask?.purpose).toBe("authorization");
		expect(ask?.items).toMatchObject({ client_id: "c1", state: "st", dpop_jkt: "jkt" });
		expect(ask?.screen).toEqual({
			eEnc,
			eSig: { kty: "EC", crv: "P-256", x: b64(32), y: b64(32, 2) },
		});
		expect(ask?.by).toBe("192.0.2.1");
	});

	it("gives the same start again the T it made, and refuses the JAR with other screen keys (A20)", async () => {
		const h = harness();
		const request = jar(claims());
		const first = await h.body(h.fields(request));
		expect(await h.body(h.fields(request))).toEqual(first);
		expect(h.asked).toHaveLength(1);
		expect(await h.body(h.fields(request, b64(32, 9)))).toMatchObject({
			status: 400,
			json: { error: "invalid_request" },
		});
		const sameJti = jar(claims({ state: "other" }));
		expect(await h.body(h.fields(sameJti))).toMatchObject({
			status: 400,
			json: { error: "invalid_request" },
		});
	});

	it("refuses a JAR not its client's, not for this issuer, with no jti, or living too long", async () => {
		const h = harness();
		const refused = (request: string) => h.body(h.fields(request)).then((r) => r.json);
		expect(await refused(jar(claims(), "c2"))).toMatchObject({ error: "invalid_request_object" });
		expect(await refused(jar(claims({ iss: "c2" })))).toMatchObject({
			error: "invalid_request_object",
		});
		expect(await refused(jar(claims({ aud: "https://other.example" })))).toMatchObject({
			error: "invalid_request_object",
		});
		expect(await refused(jar(claims({ jti: undefined })))).toMatchObject({
			error: "invalid_request_object",
		});
		expect(await refused(jar(claims({ exp: now / 1000 + 601 })))).toMatchObject({
			error: "invalid_request_object",
		});
		expect(h.asked).toHaveLength(0);
	});

	it("refuses a redirect URI the client did not register, an unknown client, and missing keys", async () => {
		const h = harness();
		expect(
			await h.body(h.fields(jar(claims({ redirect_uri: "https://evil.example/cb" })))),
		).toMatchObject({
			status: 400,
			json: { error: "invalid_request" },
		});
		expect(await h.body({ ...h.fields(jar(claims())), clientId: "c9" })).toMatchObject({
			status: 401,
			json: { error: "invalid_client" },
		});
		expect(await h.body({ ...h.fields(jar(claims())), eEnc: b64(32) })).toMatchObject({
			status: 400,
		});
	});

	it("holds every field to front-core-wire's spec before any is acted on: no client looked up, no source asked, no T made", async () => {
		let asked = 0;
		const counting: RequestSource = {
			name: "counting",
			jarOf: async () => {
				asked += 1;
				return undefined;
			},
		};
		const h = harness({ sources: [byValue, counting] });
		const refused = {
			status: 400,
			json: {
				error: "invalid_request",
				error_description: "the start's fields are not front-core-wire's",
			},
		};
		const sent = h.fields(jar(claims()));
		// Another spelling of a key's bytes: its last character's unused bits set.
		const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const respelled = (text: string) =>
			text.slice(0, -1) + letters[letters.indexOf(text.at(-1) ?? "A") | 1];
		for (const off of [
			// An unknown client with a field off its spec: the field's refusal, before the client is sought.
			{ clientId: "c9", requestUri: "x".repeat(513) },
			{ clientId: "c".repeat(65) },
			{ clientId: "c 1" },
			{ clientId: "c\ud800" },
			{ request: "not a jws" },
			{ request: `a.${"b".repeat(8189)}.c` },
			{ eSigX: respelled(sent.eSigX) },
			// A field sent as no text is not carried, never read as no JAR or no request_uri.
			{ request: 5 },
			{ requestUri: {} },
		]) {
			expect(await h.body({ ...sent, ...off })).toEqual(refused);
		}
		expect(h.sought).toEqual([]);
		expect(asked).toBe(0);
		expect(h.asked).toHaveLength(0);
		// At the bounds the fields are the wire's: a 64-character client is sought, and is unknown.
		expect(await h.body({ ...sent, clientId: "c".repeat(64) })).toMatchObject({ status: 401 });
		expect(h.sought).toEqual(["c".repeat(64)]);
	});

	it("hands the sources each field the wire names as the Front carries it: an empty one is not sent", async () => {
		const pushed: RequestSource = {
			name: "pushed",
			jarOf: async (fields) =>
				fields.requestUri === undefined ? undefined : { jar: jar(claims({ jti: "p1" })) },
		};
		const unnamed: RequestSource = {
			name: "unnamed",
			jarOf: async (fields) =>
				fields.request_uri === undefined
					? undefined
					: { refused: { error: "invalid_request_uri", description: "read" } },
		};
		const h = harness({ sources: [byValue, pushed, unnamed] });
		const sent = h.fields(jar(claims()));
		const { request: _byValue, ...keys } = sent;
		// An empty requestUri beside the JAR, or an empty request beside a requestUri: one source answers.
		expect(await h.body({ ...sent, requestUri: "" })).toMatchObject({ status: 200 });
		expect(await h.body({ ...keys, request: "", requestUri: "urn:p" })).toMatchObject({
			status: 200,
		});
		// An empty request alone is none sent: no source answers.
		expect(await h.body({ ...keys, request: "" })).toMatchObject({
			status: 400,
			json: { error: "invalid_request" },
		});
		// A member the wire does not name reaches no source.
		expect(await h.body({ ...sent, request_uri: "urn:x" })).toMatchObject({ status: 200 });
	});

	it("refuses a start naming both a request and a request_uri, whichever sources answer, and writes the request_uri a start by PAR named into T alone", async () => {
		const pushed: RequestSource = {
			name: "pushed",
			jarOf: async (fields) =>
				fields.requestUri === undefined ? undefined : { jar: jar(claims({ jti: "p2" })) },
		};
		// No source of request_uris composed: both sent is still refused, never read as by value.
		const alone = harness();
		expect(
			await alone.body({
				...alone.fields(jar(claims())),
				requestUri: "urn:ietf:params:oauth:request_uri:x",
			}),
		).toMatchObject({ status: 400, json: { error: "invalid_request" } });
		expect(alone.asked).toHaveLength(0);
		const h = harness({ sources: [byValue, pushed] });
		const { request: _none, ...keys } = h.fields(jar(claims()));
		const uri = "urn:ietf:params:oauth:request_uri:p2";
		expect(await h.body({ ...keys, requestUri: uri })).toMatchObject({ status: 200 });
		expect(h.asked.at(-1)?.items).toMatchObject({ request_uri: uri });
		expect(await h.body(h.fields(jar(claims({ jti: "v1" }))))).toMatchObject({ status: 200 });
		expect("request_uri" in (h.asked.at(-1)?.items ?? {})).toBe(false);
		// It is declared among the items authorize fills, or approvals would refuse every T naming it.
		expect(filledItems.names).toContain("request_uri");
	});

	it("answers prompt=none with login_required, takes the words every tap meets, and refuses others", async () => {
		const h = harness();
		expect(await h.body(h.fields(jar(claims({ prompt: "none" }))))).toMatchObject({
			json: { error: "login_required" },
		});
		expect(
			await h.body(h.fields(jar(claims({ jti: "j2", prompt: "login consent" })))),
		).toMatchObject({
			status: 200,
		});
		expect(await h.body(h.fields(jar(claims({ jti: "j3", prompt: "bogus" }))))).toMatchObject({
			json: { error: "invalid_request" },
		});
	});

	it("refuses a claim that is no item, and says whether a person with no passkey may create one", async () => {
		const h = harness({ allows: true });
		expect(await h.body(h.fields(jar(claims({ max_age: 60 }))))).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.body(h.fields(jar(claims({ jti: "j4" }))))).toMatchObject({
			json: { create: true },
		});
	});

	it("allows T's sign-up (F1) at its issue only where a person with no passkey may create one and a sign-up is offered", async () => {
		const continues = async (p: { allows?: boolean; signUp?: boolean }) => {
			const h = harness(p);
			expect(await h.body(h.fields(jar(claims())))).toMatchObject({ status: 200 });
			return h.asked[0]?.continues;
		};
		expect(await continues({ allows: true, signUp: true })).toEqual(["sign-up"]);
		expect(await continues({ allows: true, signUp: false })).toBeUndefined();
		expect(await continues({ allows: false, signUp: true })).toBeUndefined();
		expect(await continues({ signUp: true })).toBeUndefined();
	});

	it("takes a JAR only before its expiry, a resend of its start too", async () => {
		const h = harness();
		const request = jar(claims({ exp: now / 1000 + 60 }));
		expect(await h.body(h.fields(request))).toMatchObject({ status: 200 });
		h.at(now + 60_000);
		expect(await h.body(h.fields(request))).toMatchObject({
			status: 400,
			json: { error: "invalid_request_object" },
		});
	});

	it("makes one statement for two of the same start at once, and answers both with it", async () => {
		let go = () => {};
		const held = new Promise<void>((resolve) => {
			go = resolve;
		});
		let first = true;
		const h = harness({
			slow: async () => {
				if (first) {
					first = false;
					await held;
				}
			},
		});
		const request = jar(claims());
		const one = h.body(h.fields(request));
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(await h.body(h.fields(request))).toMatchObject({
			status: 503,
			json: { error: "temporarily_unavailable" },
		});
		go();
		expect(await one).toMatchObject({ status: 200, json: { statement: statementOf(1) } });
		expect(await h.body(h.fields(request))).toMatchObject({ json: { statement: statementOf(1) } });
		expect(h.asked).toHaveLength(1);
	});

	it("lets another call take over a making past its hold, the late call keeping nothing of its own", async () => {
		let go = () => {};
		const held = new Promise<void>((resolve) => {
			go = resolve;
		});
		let first = true;
		const h = harness({
			slow: async () => {
				if (first) {
					first = false;
					await held;
				}
			},
		});
		const request = jar(claims());
		const late = h.body(h.fields(request));
		await new Promise((resolve) => setTimeout(resolve, 10));
		h.at(now + 30_001);
		const taken = await h.body(h.fields(request));
		expect(taken).toMatchObject({ status: 200, json: { statement: statementOf(1) } });
		go();
		expect(await late).toEqual(taken);
		expect(h.asked).toHaveLength(2);
	});

	it("lets the same start try again after its statement was refused, and answers too many as 429", async () => {
		let refusing = true;
		const h = harness({ refuse: () => (refusing ? "limited" : undefined) });
		const request = jar(claims());
		expect(await h.body(h.fields(request))).toMatchObject({
			status: 429,
			json: { error: "rate_limited" },
		});
		refusing = false;
		expect(await h.body(h.fields(request))).toMatchObject({
			status: 200,
			json: { statement: statementOf(1) },
		});
	});

	it("takes the request from exactly one source, its refusal as it names it, and an aud among others", async () => {
		const refusing: RequestSource = {
			name: "refusing",
			jarOf: async (fields) =>
				fields.requestUri
					? { refused: { error: "invalid_request_uri", description: "gone" } }
					: undefined,
		};
		const h = harness({ sources: [byValue, refusing] });
		expect(await h.body({ ...h.fields(jar(claims())), requestUri: "urn:x" })).toMatchObject({
			json: { error: "invalid_request" },
		});
		const { request: _none, ...fields } = h.fields(jar(claims()));
		expect(await h.body({ ...fields, requestUri: "urn:x" })).toMatchObject({
			json: { error: "invalid_request_uri" },
		});
		expect(await h.body(fields)).toMatchObject({ json: { error: "invalid_request" } });
		const many = jar(claims({ aud: ["https://other.example", issuer] }));
		expect(await h.body(h.fields(many))).toMatchObject({ status: 200 });
	});

	it("refuses an encryption key that is no uncompressed point, before the JAR is reserved", async () => {
		const h = harness();
		const request = jar(claims());
		const compressed = Buffer.concat([Buffer.from([2]), Buffer.alloc(64, 7)]).toString("base64url");
		expect(await h.body({ ...h.fields(request), eEnc: compressed })).toMatchObject({
			json: { error: "invalid_request" },
		});
		expect(await h.body(h.fields(request))).toMatchObject({ status: 200 });
	});

	it("refuses an OpenID request before T where no ID token is made", async () => {
		const h = harness({ idTokens: false });
		expect(await h.body(h.fields(jar(claims({ scope: "openid read" }))))).toMatchObject({
			status: 400,
			json: { error: "invalid_scope" },
		});
		expect(h.asked).toHaveLength(0);
	});

	it("takes an OpenID request's claims into T, refusing before T what their reader refuses", async () => {
		const read: unknown[][] = [];
		const h = harness({
			claims: {
				refusal: (asked, openid) => {
					read.push([asked, openid]);
					return asked !== undefined && !openid ? "asked without openid" : undefined;
				},
			},
		});
		const asking = { id_token: { email: { essential: true } } };
		const openid = await h.body(h.fields(jar(claims({ scope: "openid read", claims: asking }))));
		expect(openid.status).toBe(200);
		expect(read).toEqual([[asking, true]]);
		const plain = await h.body(h.fields(jar(claims({ jti: "j9", scope: "read", claims: asking }))));
		expect(plain).toMatchObject({ status: 400, json: { error: "invalid_request_object" } });
		expect(read).toContainEqual([asking, false]);
		expect(h.asked).toHaveLength(1);
	});

	it("takes a claim asked by null into T as asked by {}, and refuses before T any null left in claims", async () => {
		const h = harness();
		const asking = { id_token: { email: null } };
		const asked = await h.body(h.fields(jar(claims({ scope: "openid read", claims: asking }))));
		expect(asked.status).toBe(200);
		expect(h.asked[0]?.items).toMatchObject({ claims: { id_token: { email: {} } } });
		const left = { id_token: { email: { essential: true, purpose: null } } };
		const refused = await h.body(
			h.fields(jar(claims({ jti: "j9", scope: "openid read", claims: left }))),
		);
		expect(refused).toMatchObject({
			status: 400,
			json: { error: "invalid_request_object", error_description: "item:claims" },
		});
		expect(h.asked).toHaveLength(1);
	});

	it("refuses before T any claims where no module reads them", async () => {
		const h = harness({ claims: claimsUnread });
		const asking = { id_token: { email: null } };
		const asked = await h.body(h.fields(jar(claims({ scope: "openid read", claims: asking }))));
		expect(asked).toMatchObject({ status: 400, json: { error: "invalid_request_object" } });
		expect(h.asked).toHaveLength(0);
		expect(await h.body(h.fields(jar(claims({ jti: "j9" }))))).toMatchObject({ status: 200 });
	});

	it("refuses, before T, a challenge not of S256's shape and a dpop_jkt out of its form", async () => {
		const h = harness();
		expect(await h.body(h.fields(jar(claims({ code_challenge: "cc" }))))).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(await h.body(h.fields(jar(claims({ jti: "j8", dpop_jkt: "bad" }))))).toMatchObject({
			json: { error: "invalid_request_object" },
		});
		expect(h.asked).toHaveLength(0);
	});

	it("reads the resource asked by the one rule, before T: none composed refuses it, as does an audience not the client's", async () => {
		/** resource-indicators' rule, as it answers: the resource alone where the client may be issued it. */
		const rule: Pick<TargetRule, "target"> = {
			target: ({ param, audience, within }) => {
				const resource = param("resource");
				if (!resource) return { kind: "audience", audience };
				return within(resource)
					? { kind: "audience", audience: [resource] }
					: {
							kind: "error",
							error: "invalid_target",
							description: "resource is not an audience this client may be issued",
						};
			},
		};
		const api = "https://api.example";
		const unruled = harness();
		expect(await unruled.body(unruled.fields(jar(claims({ resource: api }))))).toMatchObject({
			json: {
				error: "invalid_target",
				error_description: "resource is read by no rule here",
			},
		});
		expect(unruled.asked).toHaveLength(0);
		const ruled = harness({ rule });
		expect(
			await ruled.body(ruled.fields(jar(claims({ jti: "j9", resource: "https://elsewhere" })))),
		).toMatchObject({
			json: {
				error: "invalid_target",
				error_description: "resource is not an audience this client may be issued",
			},
		});
		expect(ruled.asked).toHaveLength(0);
		expect(
			(await ruled.body(ruled.fields(jar(claims({ jti: "j10", resource: api }))))).status,
		).toBe(200);
		expect(ruled.asked.map((ask) => (ask.items as { resource?: string }).resource)).toEqual([api]);
		// A rule answering anything but that resource alone (the default, unread) is refused too.
		const unread = harness({
			rule: { target: ({ audience }) => ({ kind: "audience", audience }) },
		});
		expect(
			await unread.body(unread.fields(jar(claims({ jti: "j11", resource: api })))),
		).toMatchObject({ json: { error_description: "resource is not the audience asked" } });
	});

	it("reads the resource by resource-indicators' own rule: its URI form, the client's audiences, and the issuer where it names none", async () => {
		const got = contract<readonly TargetRule[]>("test.rules");
		const reader = defineModule(
			{ name: "reader", replicaSafe: true, takes: [targetRules] },
			(m) => [m.provide(got).by((c) => c.collect(targetRules))],
		);
		const app = await assemble({
			modules: [resourceIndicators, reader],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		const [rule] = app.get(got);
		if (!rule) throw new Error("no rule composed");
		const h = harness({ rule });
		const refusedFor = async (resource: string, jti: string) =>
			((await h.body(h.fields(jar(claims({ jti, resource }))))) as { json: unknown }).json;
		expect(await refusedFor("api.example", "r1")).toMatchObject({
			error: "invalid_target",
			error_description: "resource is not an absolute URI",
		});
		expect(await refusedFor("https://api.example#f", "r2")).toMatchObject({
			error_description: "resource carries a fragment",
		});
		expect(
			(await h.body(h.fields(jar(claims({ jti: "r3", resource: "https://api.example" }))))).status,
		).toBe(200);
		// A client whose allowance names no audience is issued for the issuer: the rule takes it too.
		const allowance = client.section;
		(client as { section: unknown }).section = <T>(s: { name: string }) =>
			(s.name === redirects.name
				? allowance<T>(s as never)
				: { grants: ["authorization_code"], scopes: ["read"], audiences: [] }) as T;
		try {
			expect((await h.body(h.fields(jar(claims({ jti: "r4", resource: issuer }))))).status).toBe(
				200,
			);
			expect(await refusedFor("https://api.example", "r5")).toMatchObject({
				error_description: "resource is not an audience this client may be issued",
			});
		} finally {
			(client as { section: unknown }).section = allowance;
		}
	});

	it("asks T to fit the way back, a sign-up's continue too where it may continue, and refuses a longer one as the request object's", async () => {
		const fits = (signUp: boolean) => (signUp ? 111 : 222);
		const h = harness({ fits });
		await h.body(h.fields(jar(claims())));
		expect(h.asked[0]?.fits).toBe(222);
		const both = harness({ allows: true, signUp: true, fits });
		await both.body(both.fields(jar(claims())));
		expect(both.asked[0]?.fits).toBe(111);
		// The route contract's: its finish's statement, and the smaller with its continue's.
		const finish = requests.loginFinish.fields.find((f) => f.name === "statement")?.max ?? 0;
		const signUp = requests.continue.fields.find((f) => f.name === "statement")?.max ?? 0;
		expect([tFits(false), tFits(true)]).toEqual([finish, Math.min(finish, signUp)]);
		const long = harness({ refuse: () => "long" });
		expect(await long.body(long.fields(jar(claims())))).toEqual({
			status: 400,
			json: {
				error: "invalid_request_object",
				error_description: "the request object makes a statement too long",
			},
		});
	});

	it("refuses, before T, a client not allowed the code grant", async () => {
		const h = harness();
		const plain = {
			...client,
			section: <T>() => ({ grants: [], scopes: ["read"], audiences: [] }) as T,
		};
		const allowance = client.section;
		(client as { section: unknown }).section = <T>(s: { name: string }) =>
			(s.name === redirects.name ? allowance<T>(s as never) : plain.section<T>()) as T;
		try {
			expect(await h.body(h.fields(jar(claims())))).toMatchObject({
				json: { error: "invalid_request" },
			});
			expect(h.asked).toHaveLength(0);
		} finally {
			(client as { section: unknown }).section = allowance;
		}
	});
});
