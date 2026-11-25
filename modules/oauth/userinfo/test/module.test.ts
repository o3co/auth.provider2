import { claimsSelections } from "@mod/claims-selection";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { issuer, type MetadataItem, metadata } from "@mod/issuer";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { type ReleasedClaims, releasedClaims } from "@mod/oidc";
import { promiseNames, promises, type Stance, stances } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { rateLimit } from "@mod/rate-limit";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { sessionTokens } from "@mod/session-tokens";
import { accessTokens } from "@mod/tokens";
import { afterEach, expect, it } from "vitest";
import userinfoModule from "../src/module.ts";

let stop = async () => {};
afterEach(async () => {
	failing = undefined;
	await stop();
});
/** How sessions fail: unable to tell answers 503; anything else is not userinfo's to answer. */
let failing: "unavailable" | "bug" | undefined;
const items = contract<readonly MetadataItem[]>("items");
const declared = contract<readonly Stance[]>("declared");
/** The parts userinfo reads: every token is admitted, issued in a session no longer open. */
const parts = defineModule(
	// Safe: it keeps nothing a request writes; `failing` and `issuerUrl` are the test's settings.
	{ name: "parts", replicaSafe: true, takes: [metadata, stances] },
	(m) => [
		m.provide(senderBinding).by(
			() =>
				({
					admitted: async () => ({
						kind: "admitted",
						access: {
							kind: "valid",
							id: "t",
							grant: { subject: "ann", scope: ["openid"] },
							tokenType: "Bearer",
						},
					}),
				}) as never,
		),
		m.provide(accessTokens).by(() => ({}) as never),
		m
			.provide(sessionTokens)
			.by(() => ({ sessionOf: async () => ({ kind: "bound", handle: "h" }) }) as never),
		m.provide(sessions).by(() =>
			stubSessions({
				entryOf: async () => {
					if (failing === "unavailable") throw new Unavailable("session");
					if (failing === "bug") throw new TypeError("bug");
					return { kind: "absent" };
				},
			}),
		),
		m.provide(releasedClaims).by(() => ({ of: async () => ({}) }) as ReleasedClaims),
		m.provide(claimsSelections).by(() => ({ forToken: async () => undefined }) as never),
		m.provide(items).by((c) => c.collect(metadata)),
		// Every request is let through: what is counted is the handler's own test.
		m.provide(rateLimit).by(() => ({ hit: async () => ({ kind: "allowed" as const }) })),
		m.provide(declared).by((c) => c.collect(stances)),
		m
			.provide(issuer)
			.by(() => ({ url: "https://as.example", endpointOrigin: "https://as.example" })),
	],
);

let logged = recordingLog();
async function serve() {
	logged = recordingLog();
	const app = await assemble(composition());
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/userinfo`;
	return { app, url };
}

/** userinfo beside http and the parts it reads, on many instances, reached at its public origin. */
function composition() {
	return {
		modules: [http, testServer(), parts, userinfoModule],
		config: {
			// Many instances: userinfo keeps nothing, so it never refuses them.
			...kernelConfig({ deployment: "multi" }),
			...httpConfig({
				"public-origin": "https://as.example",
				"cors-origins": ["https://app.example"],
				"trusted-proxies": ["127.0.0.1"],
			}),
		},
		runtime: quietRuntime({ log: logged.log }),
	};
}

it("serves GET and POST, with or without a body, refusing a token whose session ended, never stored [oidc-core-5.3-a] [rfc6750-3.1-b]", async () => {
	const { url } = await serve();
	const sent = {
		authorization: "Bearer t",
		"x-forwarded-proto": "https",
		"x-forwarded-for": "192.0.2.1",
	};
	const requests: [string, RequestInit][] = [
		["GET", { method: "GET", headers: sent }],
		["POST", { method: "POST", headers: sent }],
		["POST form", { method: "POST", headers: sent, body: new URLSearchParams({ a: "b" }) }],
		[
			"POST json",
			{ method: "POST", headers: { ...sent, "content-type": "application/json" }, body: "{}" },
		],
	];
	for (const [method, init] of requests) {
		const res = await fetch(url, init);
		expect([method, res.status, res.headers.get("cache-control"), await res.json()]).toEqual([
			method,
			401,
			"no-store",
			{ error: "invalid_token" },
		]);
	}
});

it("answers 503 when a check cannot tell, never stored, as http warns of it by what failed and the route", async () => {
	const { url } = await serve();
	failing = "unavailable";
	const res = await fetch(url, {
		headers: {
			authorization: "Bearer t",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "192.0.2.1",
		},
	});
	expect([res.status, res.headers.get("cache-control"), await res.json()]).toEqual([
		503,
		"no-store",
		{ error: "temporarily_unavailable" },
	]);
	// http answers it, by the route's declared answer, and warns of it once.
	expect(logged.lines().filter((l) => l.event.endsWith(".unavailable"))).toEqual([
		{
			level: "warn",
			event: "http.unavailable",
			fields: { what: "session", route: "/oauth/userinfo" },
		},
	]);
});

it("leaves an error that is not an inability to tell to http, neither 503 nor logged as unavailable", async () => {
	const { url } = await serve();
	failing = "bug";
	const res = await fetch(url, {
		headers: {
			authorization: "Bearer t",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "192.0.2.1",
		},
	});
	expect(res.status).toBe(500);
	expect(logged.lines().filter((l) => l.event.endsWith(".unavailable"))).toEqual([]);
});

it("answers no token it was presented and logs none, refusing it or unable to tell [rfc9700-4.9.3-a]", async () => {
	const { url } = await serve();
	const headers = {
		authorization: "Bearer s3cr3t-token",
		"x-forwarded-proto": "https",
		"x-forwarded-for": "192.0.2.1",
	};
	const seen: unknown[] = [];
	for (const fails of [undefined, "unavailable", "bug"] as const) {
		failing = fails;
		const res = await fetch(url, { headers });
		seen.push([res.status, [...res.headers], await res.text()]);
	}
	expect(seen.map((answer) => (answer as [number])[0])).toEqual([401, 503, 500]);
	expect(JSON.stringify([seen, logged.lines()])).not.toContain("s3cr3t");
});

it("lets a listed origin's page send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait [oidc-core-5.3-c]", async () => {
	const { url } = await serve();
	const res = await fetch(url, {
		method: "OPTIONS",
		headers: {
			origin: "https://app.example",
			"access-control-request-method": "GET",
			"access-control-request-headers": "authorization, dpop, content-type",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "192.0.2.1",
		},
	});
	expect(res.headers.get("access-control-allow-origin")).toBe("https://app.example");
	const allowed = (res.headers.get("access-control-allow-headers") ?? "").toLowerCase();
	for (const name of ["authorization", "dpop", "content-type"]) expect(allowed).toContain(name);
	const got = await fetch(url, {
		headers: {
			origin: "https://app.example",
			authorization: "Bearer t",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "192.0.2.1",
		},
	});
	expect(got.headers.get("access-control-expose-headers")?.toLowerCase().split(/,\s*/)).toEqual(
		expect.arrayContaining(["www-authenticate", "dpop-nonce", "retry-after"]),
	);
});

it("names itself in the issuer's metadata, an https URL on the public origin [oidc-discovery-3-h] [oidc-core-1.2-a]", async () => {
	const { app } = await serve();
	expect(app.get(items)).toContainEqual({
		name: "userinfo_endpoint",
		value: "https://as.example/oauth/userinfo",
	});
});

it("declares both promises a compromised Front must not break broken, and none of the log's (G1)", async () => {
	const { app } = await serve();
	const stood = app.get(declared);
	expect(stood.map((s) => [s.promise, s.holds, s.by, s.setting])).toEqual([
		[promiseNames.newAuthorization, false, "userinfo", undefined],
		[promiseNames.clientToken, false, "userinfo", undefined],
	]);
	expect(stood[0]?.reason).toContain("any sub and attributes");
	expect(stood[1]?.reason).toContain("in place of checking the token");
});

it("leaves both promises not holding where composed, and refuses boot where a deployment requires either (G1)", async () => {
	const app = await assemble({
		...composition(),
		modules: [...composition().modules, promisesModule],
	});
	const judged = app.get(promises).judgment();
	for (const name of [promiseNames.newAuthorization, promiseNames.clientToken]) {
		const judgment = judged.find((j) => j.promise === name);
		expect([judgment?.held, judgment?.breaking.map((b) => b.by)], name).toEqual([
			false,
			["userinfo"],
		]);
	}
	for (const name of [promiseNames.newAuthorization, promiseNames.clientToken]) {
		const base = composition();
		const refused = await assemble({
			...base,
			modules: [...base.modules, promisesModule],
			config: { ...base.config, promises: { required: [name] } },
		}).catch((e: unknown) => e);
		expect(BootRefused.is(refused), name).toBe(true);
		expect(JSON.stringify((refused as BootRefused).refusals), name).toContain("userinfo");
	}
});

it("takes all it names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(composition()))["userinfo"]).toBeUndefined();
});
