import type { Approvals, IssueAsk } from "@mod/approvals";
import type { Client } from "@mod/clients";
import type { HttpRequest } from "@mod/http";
import { redirects } from "@mod/redirect-uris";
import { typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import type { JarReservations, RequestSource, StoredReservation } from "../src/contract.ts";
import { reserving } from "../src/jar/jar.ts";
import { byValue, starting } from "../src/start/start.ts";

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
			: { grants: ["authorization_code"], scopes: ["read"], audiences: [] }) as T,
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

function harness(
	p: {
		allows?: boolean;
		refuse?: () => string | undefined;
		sources?: readonly RequestSource[];
		slow?: () => Promise<void>;
		/** Whether an ID token is made; made unless told otherwise. */
		idTokens?: boolean;
	} = {},
) {
	const asked: IssueAsk[] = [];
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
			return { kind: "issued", statement: `T${n}`, hash: `h${n}`, challenge: `ch${n}` };
		},
	};
	const start = starting({
		clients: { find: async (id) => (id === "c1" ? client : undefined) },
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
		withoutPasskey: p.allows === undefined ? undefined : { allows: async () => p.allows === true },
		idTokens: p.idTokens ?? true,
		bindings: {
			requestedOf: (param) => {
				const jkt = param("dpop_jkt");
				if (jkt === "bad") return { kind: "malformed", parameter: "dpop_jkt" };
				return jkt === undefined
					? { kind: "none" }
					: { kind: "requested", binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" } };
			},
		},
	});
	const send = (fields: Record<string, string>) =>
		start({ json: fields, source: { address: "192.0.2.1" } } as unknown as HttpRequest);
	const body = (fields: Record<string, string>) =>
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
	return { asked, body, fields, at };
}

describe("a login's start (②)", () => {
	it("issues T over the JAR's items and the screen's keys, and answers it with its challenge", async () => {
		const h = harness();
		const r = await h.body(h.fields(jar(claims())));
		expect(r).toEqual({ status: 200, json: { statement: "T1", challenge: "ch1", create: false } });
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
		expect(await one).toMatchObject({ status: 200, json: { statement: "T1" } });
		expect(await h.body(h.fields(request))).toMatchObject({ json: { statement: "T1" } });
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
		expect(taken).toMatchObject({ status: 200, json: { statement: "T1" } });
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
			json: { statement: "T1" },
		});
	});

	it("takes the request from exactly one source, its refusal as it names it, and an aud among others", async () => {
		const refusing: RequestSource = {
			name: "refusing",
			jarOf: async (fields) =>
				fields.request_uri
					? { refused: { error: "invalid_request_uri", description: "gone" } }
					: undefined,
		};
		const h = harness({ sources: [byValue, refusing] });
		expect(await h.body({ ...h.fields(jar(claims())), request_uri: "urn:x" })).toMatchObject({
			json: { error: "invalid_request" },
		});
		const { request: _none, ...fields } = h.fields(jar(claims()));
		expect(await h.body({ ...fields, request_uri: "urn:x" })).toMatchObject({
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

	it("takes an OpenID request's claims into T, refusing before T one malformed or asked without openid", async () => {
		const h = harness();
		const asking = { id_token: { email: { essential: true } } };
		const openid = await h.body(h.fields(jar(claims({ scope: "openid read", claims: asking }))));
		expect(openid.status).toBe(200);
		expect(h.asked).toHaveLength(1);
		for (const [jti, asked] of [
			["j9", { scope: "read", claims: { id_token: {} } }],
			["j10", { scope: "openid read", claims: { id_token: { email: { values: [] } } } }],
			["j11", { scope: "openid read", claims: [] }],
		] as const) {
			expect(await h.body(h.fields(jar(claims({ jti, ...asked }))))).toMatchObject({
				status: 400,
				json: { error: "invalid_request_object" },
			});
		}
		expect(h.asked).toHaveLength(1);
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
