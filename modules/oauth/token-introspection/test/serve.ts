import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { type HttpSettings, httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { type AccessGrant, accessTokenIssuance, accessTokens, type IssueLimits } from "@mod/tokens";
import { issueAtOnce, tokensStandIn } from "@mod/tokens/testing";
import { afterEach } from "vitest";
import tokenIntrospection from "../src/module.ts";

const logged = recordingLog();
/** The composition's clock: fixed where the tests start, moved on only by `later`, so no boundary rests on real time. */
const startedAt = Date.now();
let ahead = 0;
/** What the composition's clock reads now. */
export const clockNow = () => startedAt + ahead;
const runtime = quietRuntime({ log: logged.log, clock: { now: clockNow } });

let stop = async () => {};
afterEach(() => {
	ahead = 0;
	return stop();
});

/** Moves the composition's clock on by this much. */
export const later = (ms: number) => {
	ahead += ms;
};

export type Form = Record<string, string> | [string, string][];

/** The modules every composition here holds, then `extra`. */
export const introspectionModules = (...extra: Module[]): Module[] => [
	http,
	testServer(),
	tokensStandIn(),
	issuerModule,
	clientsModule,
	secretHashModule,
	clientAllowanceModule,
	tokenIntrospection,
	...extra,
];

/** Their configuration, reached at `origin`, with http's settings `peer` beside it. */
export const introspectionConfig = (origin: string, peer: Partial<HttpSettings> = {}) => ({
	...kernelConfig(),
	...httpConfig({ "public-origin": origin, ...peer }),
	...issuerConfig({ url: origin }),
});

const confidential = (id: string, audiences: string[]) =>
	confidentialClient({ id, sections: allowancesFor({ scopes: ["read"], audiences }) });

/**
 * token-introspection over the tokens stand-in. "app" holds tokens for https://api, "api" shares that
 * audience, "other" sees another, and "pub" is public. `limit` sets the section and counts requests
 * for real; otherwise nothing is limited.
 */
export async function serve(
	options: { extra?: Module[]; http?: Partial<HttpSettings>; limit?: Record<string, unknown> } = {},
) {
	const recorded = auditStandIn();
	const app = await assemble({
		modules: introspectionModules(
			recorded.module,
			...(options.limit ? [rateLimitModule, simulatedStore().module] : [rateLimitStandIn]),
			...(options.extra ?? []),
		),
		config: {
			...introspectionConfig("https://issuer.example", options.http),
			...clientsConfig([
				confidential("app", ["https://api"]),
				confidential("api", ["https://api"]),
				confidential("other", ["https://elsewhere"]),
				publicClient({ id: "pub" }),
			]),
			...(options.limit ? { "token-introspection": options.limit } : {}),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** Posts `form` as client `as`, or as the form's own credentials when `as` is undefined. */
	const post = async (as: string | undefined, form: Form) => {
		const body = new URLSearchParams(form);
		if (as !== undefined) {
			body.append("client_id", as);
			body.append("client_secret", clientSecret(as));
		}
		const res = await fetch(`${base}/oauth/introspect`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		const text = await res.text();
		const json = (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>;
		return { status: res.status, headers: res.headers, text, json, error: json.error };
	};
	// A token "app" holds for itself, for its audience and its scope.
	const grant = {
		subject: "app",
		subjectKind: "client" as const,
		issuedTo: "app",
		audience: ["https://api"],
		scope: ["read"],
	};
	/** Issues "app"'s own token, or one with `as` in its grant, such as a person's. */
	const issue = async (limits?: IssueLimits, as: Partial<AccessGrant> = {}) => {
		const asked = { grant: { ...grant, ...as }, grantType: "client_credentials" };
		const issued = await issueAtOnce(app.get(accessTokenIssuance), asked, limits);
		if (issued.kind !== "issued") throw new Error(issued.reason);
		return issued.access.token;
	};
	const active = async (token: string) => (await post("app", { token })).json.active as boolean;
	/** The warnings logged since this composition was made. */
	const from = logged.lines().length;
	const warnings = () =>
		logged
			.lines()
			.slice(from)
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	const revoke = (token: string) => app.get(accessTokens).revokeAccess(token);
	return { base, post, issue, revoke, active, events: recorded.events, warnings };
}
