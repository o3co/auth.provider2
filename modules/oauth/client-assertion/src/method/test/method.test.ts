import type { Client } from "@mod/clients";
import { testRequest } from "@mod/http/testing";
import { BootRefused, isUnavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { CompactSign, EncryptJWT, FlattenedSign } from "jose";
import { describe, expect, it } from "vitest";
import { composed } from "../../../test/composed.ts";
import { assertionMethod, assertionType, type Parts } from "../../method/method.ts";

let now = 1_800_000_000_000;
const {
	issuer,
	tokenUrl,
	seconds,
	recorded,
	lastWarned,
	looked,
	runtime,
	ecPair,
	ec,
	rsa,
	jwk,
	boot,
	claims,
	sign,
	signedWithSecret,
	unsigned,
	asked,
	posted,
	presenting,
	outcome,
	tried,
} = composed(() => now);

describe("private_key_jwt", () => {
	it("authenticates a client by an assertion signed with its key, for the issuer as one string [rfc7523-3-i] [rfc7521-5.2-h] [oidc-core-9-j]", async () => {
		const { c } = await boot();
		expect(await tried(c)).toBe("app");
		expect(await tried(c, {}, { client_id: "app" })).toBe("app");
		expect(await tried(c, { aud: `${issuer}/other` })).toBe("bad_credentials");
	});

	it("refuses an assertion for the token endpoint, or naming its audience in a list, before spending its jti", async () => {
		const { c } = await boot();
		for (const aud of [tokenUrl, [issuer], [tokenUrl], ["x", issuer], [issuer, tokenUrl]]) {
			expect(await tried(c, { aud, jti: "kept" }), JSON.stringify(aud)).toBe("bad_credentials");
			expect(lastWarned()).toBe("audience");
		}
		expect(await tried(c, { jti: "kept" })).toBe("app");
	});

	it("declares its credentials need a key the client alone holds, an asymmetric signature, which clients' boot check holds it to", async () => {
		expect(assertionMethod({ algorithms: ["ES256"] } as unknown as Parts).keyHeld).toBe(true);
		// Composed with its default algorithms, the declaration passes clients' check.
		const { c } = await boot();
		expect(c.methods()).toContain("private_key_jwt");
	});

	it("also takes the token endpoint's location, and lists, from a client accepting a loose audience, logging each", async () => {
		const tenant = `${issuer}/tenant`;
		const { c } = await boot({ issuerUrl: tenant, loose: ["app"] });
		const loosely = () =>
			recorded.lines().filter((line) => line.event === "client-assertion.loose_audience");
		const before = loosely().length;
		expect(await tried(c, { aud: tenant })).toBe("app");
		expect(loosely()).toHaveLength(before);
		for (const aud of [tokenUrl, [tokenUrl], ["x", tenant]]) {
			expect(await tried(c, { aud }), JSON.stringify(aud)).toBe("app");
		}
		expect(loosely()).toHaveLength(before + 3);
		expect(loosely().at(-1)).toMatchObject({ level: "warn", fields: { client: "app" } });
		// The token endpoint's own location, whatever path the issuer has.
		expect(await tried(c, { aud: `${tenant}/oauth/token` })).toBe("bad_credentials");
		expect(await tried(c, { aud: ["x"] })).toBe("bad_credentials");
		// Each client's own: another is held to the issuer alone.
		const twin = { iss: "app:twin", sub: "app:twin" };
		expect(await tried(c, { ...twin, aud: tokenUrl })).toBe("bad_credentials");
		expect(await tried(c, { ...twin, aud: tenant })).toBe("app:twin");
		const nowhere = await boot({ tokenEndpoint: null }).catch((error) => error);
		expect(nowhere).toBeInstanceOf(BootRefused);
		// The token endpoint has a location on the issuer's origin wherever it is composed: the public
		// origin, not the location, is what boot asks for.
		const unplaced = await boot({ publicOrigin: false }).catch((error) => error);
		expect(unplaced).toMatchObject({
			refusals: expect.arrayContaining([
				{
					where: "client-assertion",
					reason: "the token endpoint's location needs a public origin",
				},
			]),
		});
	});

	it("takes the client from client_id when given, which the assertion's issuer and subject must match [rfc7523-3-g] [rfc7521-5.2-f] [oidc-core-9-i] [rfc7521-5.2-c] [oidc-core-9-h] [rfc7521-4.2-c]", async () => {
		const { c } = await boot();
		expect(await tried(c, {}, { client_id: "other" })).toBe("unknown_client");
		expect(await tried(c, { sub: "x" })).toBe("bad_credentials");
		expect(await tried(c, { iss: "x" }, { client_id: "app" })).toBe("bad_credentials");
		expect(await outcome(c, presenting("not.a.jwt"))).toBe("unknown_client");
		// A non-string iss names no client: no lookup ever gets 7.
		expect(await tried(c, { iss: 7 })).toBe("unknown_client");
		expect(looked).not.toContain(7);
		expect(await tried(c, { iss: "x", sub: "x" }, { client_id: "app" })).toBe("bad_credentials");
	});

	it("refuses an assertion without iss, sub, aud, jti or exp [oidc-core-9-n] [rfc7521-5.2-b] [rfc7521-5.2-e] [rfc7523-3-b] [rfc7523-3-f]", async () => {
		const { c } = await boot();
		for (const claim of ["iss", "sub", "aud", "jti", "exp"]) {
			expect(await tried(c, { [claim]: undefined }, { client_id: "app" }), claim).toBe(
				"bad_credentials",
			);
		}
		// Without client_id, an assertion naming no issuer names no client.
		expect(await tried(c, { iss: undefined })).toBe("unknown_client");
		expect(await tried(c, {}, { client_id: "app" })).toBe("app");
	});

	it("compares iss, sub and aud as written, normalizing neither side [rfc7521-5.1-b] [rfc7523-3-d] [rfc7521-5.1-d] [rfc7523-3-k]", async () => {
		const { c } = await boot({ loose: ["app"] });
		const asApp = (extra: Record<string, unknown>) => tried(c, extra, { client_id: "app" });
		for (const id of ["App", "APP", "app ", " app"]) {
			expect(await asApp({ iss: id }), `iss ${id}`).toBe("bad_credentials");
			expect(await asApp({ sub: id }), `sub ${id}`).toBe("bad_credentials");
		}
		for (const aud of [
			`${issuer}/`,
			"HTTPS://issuer.example",
			"https://ISSUER.example",
			"https://issuer.example:443",
			`${tokenUrl}/`,
			"https://issuer.example/oauth/../oauth/token",
		]) {
			expect(await asApp({ aud }), aud).toBe("bad_credentials");
		}
		expect(await asApp({})).toBe("app");
		expect(await asApp({ aud: tokenUrl })).toBe("app");
	});

	it("ignores the claims it does not understand [oidc-core-9-o]", async () => {
		const { c } = await boot();
		expect(await tried(c, { ext: "x", nested: { a: [1] }, nonce: "n", azp: "other" })).toBe("app");
	});

	it("takes an assertion once per client and jti [oidc-core-9-l]", async () => {
		const { c } = await boot();
		const once = await sign(claims({ jti: "same" }));
		expect(await outcome(c, presenting(once))).toBe("app");
		expect(await outcome(c, presenting(once))).toBe("bad_credentials");
		expect(lastWarned()).toBe("used before");
		expect(await tried(c, { jti: "same" })).toBe("bad_credentials");
		// Another client's jti is its own, however the two read side by side.
		const twin = (jti: string) => tried(c, { iss: "app:twin", sub: "app:twin", jti });
		expect(await twin("same")).toBe("app:twin");
		expect(await tried(c, { jti: "twin:next" })).toBe("app");
		expect(await twin("next")).toBe("app:twin");
		expect(await tried(c, { jti: ":twin-joined" })).toBe("app");
		expect(await twin("-joined")).toBe("app:twin");
	});

	it("spends the jti last, and remembers it past the assertion's end [oidc-core-9-l]", async () => {
		const { c } = await boot();
		expect(await tried(c, { jti: "late", aud: "elsewhere" })).toBe("bad_credentials");
		expect(await tried(c, { jti: "late" })).toBe("app");
		const kept = () => tried(c, { jti: "kept", exp: seconds() + 10 });
		expect(await kept()).toBe("app");
		// Past exp and the widest allowance a section takes, whatever is set.
		now += 10_000 + 300_000;
		expect(await kept()).toBe("bad_credentials");
		// Within the store's clock margin.
		now += 59_999;
		expect(await kept()).toBe("bad_credentials");
		// Past the margin.
		now += 1;
		expect(await kept()).toBe("app");
	});

	it("keeps a spent jti past the widest clock-skew, so one widened on the same store takes it no more [guarantee-5-d]", async () => {
		const stand = memoryRecords<true>(() => now, { shards: 1, perShard: 1 });
		const narrow = await boot({ stand, settings: { "clock-skew": "0s" } });
		const once = await sign(claims({ jti: "widened", exp: seconds() + 10 }));
		expect(await outcome(narrow.c, presenting(once))).toBe("app");
		// Started again on the same store with the widest skew, the very assertion still within it.
		const wide = await boot({ stand, settings: { "clock-skew": "5m" } });
		now += 10_000 + 299_000;
		expect(await outcome(wide.c, presenting(once))).toBe("bad_credentials");
		expect(lastWarned()).toBe("used before");
		// A fresh jti signed the same way is taken: the time still holds, so the refusal is the record's.
		expect(await tried(wide.c, { jti: "widened-fresh", exp: seconds() - 299 })).toBe("app");
	});

	it("is unavailable when the store cannot tell", async () => {
		const { c, down } = await boot();
		down.failNext("save");
		await expect(c.authenticate(presenting(await sign(claims())))).rejects.toSatisfy(isUnavailable);
	});

	it("bounds the assertion's times by the lifetime cap and the clock allowance, taking none on or after its exp but within the configured clock-skew (RFC 7519 §4.1.4's leeway) [rfc7523-3-m] [rfc7521-5.2-j] [rfc7523-3-o] [rfc7521-5.2-l] [rfc7523-3-q] [oidc-core-9-m]", async () => {
		const { c } = await boot();
		const at = (extra: Record<string, unknown>) => tried(c, extra);
		expect(await at({ exp: seconds() - 29 })).toBe("app");
		expect(await at({ exp: seconds() - 30 })).toBe("bad_credentials");
		expect(await at({ exp: seconds() + 3630 })).toBe("app");
		expect(await at({ exp: seconds() + 3631 })).toBe("bad_credentials");
		expect(await at({ exp: undefined })).toBe("bad_credentials");
		expect(await at({ iat: seconds() + 30 })).toBe("app");
		expect(await at({ iat: seconds() + 31 })).toBe("bad_credentials");
		// Its `exp` less its `iat`, with no skew: each within reach, the two further apart than the cap.
		expect(await at({ iat: seconds() - 1800, exp: seconds() + 1800 })).toBe("app");
		expect(await at({ iat: seconds() - 1801, exp: seconds() + 1800 })).toBe("bad_credentials");
		expect(await at({ iat: seconds() - 1810, exp: seconds() + 1810 })).toBe("bad_credentials");
		expect(await at({ nbf: seconds() + 30 })).toBe("app");
		expect(await at({ nbf: seconds() + 31 })).toBe("bad_credentials");
		expect(await at({ jti: undefined })).toBe("bad_credentials");
		expect(await at({ jti: "j".repeat(256) })).toBe("app");
		expect(await at({ jti: "j".repeat(257) })).toBe("bad_credentials");
		expect(await at({ jti: "" })).toBe("bad_credentials");
		expect(await at({ jti: "j\ud800" })).toBe("bad_credentials");
	});

	it("logs why it refused an assertion [rfc7523-3-u] [rfc7521-5.2-n] [rfc7523-3-y]", async () => {
		const { c } = await boot({
			keys: [jwk(ec.publicKey, { kid: "ec" }), jwk(ecPair().publicKey, { kid: "ec" })],
		});
		const single = await boot();
		const reason = async (assertion: string, at = single.c) => {
			expect(await outcome(at, presenting(assertion, { client_id: "app" }))).toBe(
				"bad_credentials",
			);
			return lastWarned();
		};
		const other = ecPair();
		expect(await reason("not.a.jwt")).toBe("not a JWT");
		expect(await reason(await sign(claims({ exp: undefined })))).toBe("not a JWT");
		expect(await reason(await sign(claims({ jti: 7 })))).toBe("missing or malformed claims");
		// RS256 is not taken by default: refused by its algorithm before any key is tried.
		expect(await reason(await sign(claims(), rsa.privateKey, { alg: "RS256", kid: "ec" }))).toBe(
			"algorithm",
		);
		expect(await reason(await sign(claims()), c)).toBe("more than one key fits");
		expect(await reason(await sign(claims(), other.privateKey))).toBe("signature");
		expect(await reason(await signedWithSecret())).toBe("algorithm");
		expect(await reason(await sign(claims({ exp: seconds() - 30 })))).toBe("expired");
		expect(await reason(await sign(claims({ nbf: seconds() + 31 })))).toBe("not yet valid");
		expect(await reason(await sign(claims({ iat: seconds() + 31 })))).toBe("issued in the future");
		expect(await reason(await sign(claims({ exp: seconds() + 3631 })))).toBe("lives too long");
		expect(await reason(await sign(claims({ iat: seconds() - 3631 })))).toBe("lives too long");
		expect(await reason(await sign(claims({ iss: "x" })))).toBe("issuer");
		expect(await reason(await sign(claims({ sub: "x" })))).toBe("issuer");
		expect(await reason(await sign(claims({ aud: "x" })))).toBe("audience");
		// The times are judged before the issuer and the audience.
		expect(await reason(await sign(claims({ aud: "x", exp: seconds() - 30 })))).toBe("expired");
	});

	it("refuses an assertion with no signature, under alg none, or with a MAC [oidc-discovery-3-ae] [rfc7521-3-b] [rfc7523-3-s]", async () => {
		const { c } = await boot();
		for (const assertion of [unsigned(), `${unsigned()}AAAA`, await signedWithSecret()]) {
			expect(await outcome(c, presenting(assertion, { client_id: "app" })), assertion).toBe(
				"bad_credentials",
			);
			expect(lastWarned(), assertion).toBe("algorithm");
		}
		expect(await outcome(c, presenting(unsigned()))).toBe("bad_credentials");
	});

	it("takes only a JWT: no unencoded payload, and no critical header [rfc7523-3-y]", async () => {
		const { c } = await boot();
		const payload = new TextEncoder().encode(JSON.stringify(claims()));
		const signed = (header: Record<string, unknown>) =>
			new CompactSign(payload)
				.setProtectedHeader({ alg: "ES256", kid: "ec", ...header })
				.sign(ec.privateKey);
		const flat = await new FlattenedSign(payload)
			.setProtectedHeader({ alg: "ES256", kid: "ec", b64: false, crit: ["b64"] })
			.sign(ec.privateKey);
		const unencoded = `${flat.protected}.${flat.payload}.${flat.signature}`;
		expect(await outcome(c, presenting(unencoded, { client_id: "app" }))).toBe("bad_credentials");
		const encodedButMarked = await signed({ b64: true, crit: ["b64"] });
		expect(await outcome(c, presenting(encodedButMarked))).toBe("bad_credentials");
		expect(await outcome(c, presenting(await signed({ b64: true })))).toBe("bad_credentials");
		const extended = await new CompactSign(payload)
			.setProtectedHeader({ alg: "ES256", kid: "ec", crit: ["x-ext"], "x-ext": 1 })
			.sign(ec.privateKey, { crit: { "x-ext": true } });
		expect(await outcome(c, presenting(extended))).toBe("bad_credentials");
		expect(lastWarned()).toBe("not a JWT");
		expect(await outcome(c, presenting(await signed({})))).toBe("app");
	});

	it("refuses an assertion RFC 7519 makes invalid in the other ways: encrypted, nested, not yet valid, or its payload no claims set [rfc7523-3-y]", async () => {
		const { c } = await boot();
		const encrypted = await new EncryptJWT(claims())
			.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
			.encrypt(new Uint8Array(32));
		const nested = await new CompactSign(new TextEncoder().encode(await sign(claims())))
			.setProtectedHeader({ alg: "ES256", kid: "ec", cty: "JWT" })
			.sign(ec.privateKey);
		const listed = await new CompactSign(new TextEncoder().encode(JSON.stringify([claims()])))
			.setProtectedHeader({ alg: "ES256", kid: "ec" })
			.sign(ec.privateKey);
		const cases: Record<string, [string, string]> = {
			encrypted: [encrypted, "not a JWT"],
			nested: [nested, "not a JWT"],
			"a list for claims": [listed, "not a JWT"],
			"not yet valid": [await sign(claims({ nbf: seconds() + 31 })), "not yet valid"],
			"exp no number": [await sign(claims({ exp: String(seconds() + 60) })), "not a JWT"],
		};
		for (const [name, [assertion, reason]] of Object.entries(cases)) {
			expect(await outcome(c, presenting(assertion, { client_id: "app" })), name).toBe(
				"bad_credentials",
			);
			expect(lastWarned(), name).toBe(reason);
		}
	});

	it("takes one JWT only, never two joined [rfc7523-2.2-a]", async () => {
		const { c } = await boot();
		const [one, two] = [await sign(claims()), await sign(claims())];
		for (const joined of [`${one}.${two}`, `${one} ${two}`, `${one},${two}`, `${one}${two}`]) {
			expect(await outcome(c, presenting(joined, { client_id: "app" })), joined).toBe(
				"bad_credentials",
			);
			expect(lastWarned(), joined).toBe("not a JWT");
		}
		expect(await outcome(c, presenting(one, { client_id: "app" }))).toBe("app");
	});

	it("answers an assertion, its type or the client id given twice as malformed, before judging or spending any", async () => {
		const { c } = await boot();
		const first = await sign(claims());
		const twice = {
			"the assertion": asked({
				client_assertion_type: assertionType,
				client_assertion: [first, await sign(claims())],
			}),
			"its type": asked({
				client_assertion_type: [assertionType, assertionType],
				client_assertion: first,
			}),
			"the client id": asked({
				client_assertion_type: assertionType,
				client_assertion: first,
				client_id: ["app", "other"],
			}),
		};
		for (const [name, request] of Object.entries(twice)) {
			expect(await outcome(c, request), name).toBe("malformed_credentials");
		}
		expect(await outcome(c, presenting(first))).toBe("app");
	});

	it("takes an assertion from a JSON body as from a form", async () => {
		const { c } = await boot();
		const json = async (extra: Record<string, unknown> = {}) =>
			outcome(
				c,
				posted({
					client_assertion_type: assertionType,
					client_assertion: await sign(claims()),
					...extra,
				}),
			);
		expect(await json()).toBe("app");
		expect(await json({ client_id: "app" })).toBe("app");
		expect(await json({ client_id: "other" })).toBe("unknown_client");
		expect(await json({ client_assertion: "" })).toBe("malformed_credentials");
		expect(await outcome(c, posted({ client_assertion_type: assertionType }))).toBe(
			"malformed_credentials",
		);
		expect(await outcome(c, posted({ client_assertion: await sign(claims()) }))).toBe(
			"malformed_credentials",
		);
	});

	it("answers a part of a JSON body that is not a string as malformed, before judging or spending any", async () => {
		const { c } = await boot();
		const first = await sign(claims());
		const mistyped = {
			"the assertion as a list": {
				client_assertion_type: assertionType,
				client_assertion: [first],
			},
			"the assertion as a number": { client_assertion_type: assertionType, client_assertion: 7 },
			"the type as a list": { client_assertion_type: [assertionType], client_assertion: first },
			"the type alone, as a number": { client_assertion_type: 1 },
			"the client id as a number": {
				client_assertion_type: assertionType,
				client_assertion: first,
				client_id: 7,
			},
		};
		for (const [name, json] of Object.entries(mistyped)) {
			expect(await outcome(c, posted(json)), name).toBe("malformed_credentials");
		}
		expect(
			await outcome(c, posted({ client_assertion_type: assertionType, client_assertion: first })),
		).toBe("app");
	});

	it("reads the body's client_assertion only, never the query, where an assertion would be logged, nor a header [rfc6749-2.3.1-b] [oidc-core-9-p]", async () => {
		const { c } = await boot();
		const query = new Map([
			["client_assertion_type", [assertionType]],
			["client_assertion", [await sign(claims())]],
		]);
		expect(await outcome(c, testRequest({ method: "POST", query }))).toBe("no_credentials");
		const halves = testRequest({
			method: "POST",
			query: new Map([["client_assertion", [await sign(claims())]]]),
			json: { client_assertion_type: assertionType },
		});
		expect(await outcome(c, halves)).toBe("malformed_credentials");
		const inHeader = testRequest({
			method: "POST",
			headers: new Map([["authorization", `Bearer ${await sign(claims())}`]]),
			form: new Map([["client_id", ["app"]]]),
		});
		expect(await outcome(c, inHeader)).toBe("wrong_method");
		const otherField = asked({
			client_assertion_type: assertionType,
			assertion: await sign(claims()),
			client_id: "app",
		});
		expect(await outcome(c, otherField)).toBe("malformed_credentials");
	});

	it("is unavailable, and spends nothing, when the client's keys cannot be had", async () => {
		const saved: string[] = [];
		const method = assertionMethod({
			spent: {
				save: async (name) => {
					saved.push(name);
					return "created";
				},
			},
			jwt: {
				algorithms: ["ES256"],
				verifierOf: () => ({ verify: async () => ({ kind: "unavailable" }) }),
			},
			issuer,
			tokenEndpoint: tokenUrl,
			algorithms: ["ES256"],
			maxLifetimeMs: 3_600_000,
			skewMs: 30_000,
			clock: runtime.clock,
			log: runtime.log,
		});
		const client = { id: "app", section: () => ({ keys: [] }) } as unknown as Client;
		await expect(method.verify(presenting(await sign(claims())), client)).rejects.toSatisfy(
			isUnavailable,
		);
		expect(saved).toEqual([]);
	});
});
