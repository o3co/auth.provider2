import { auditStandIn } from "@mod/audit/testing";
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
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { accessTokenIssuance, accessTokens, type Tokens } from "@mod/tokens";
import { issueAtOnce, tokensStandIn } from "@mod/tokens/testing";
import { afterEach } from "vitest";
import tokenRevocation from "../src/module.ts";

const logged = recordingLog();
const runtime = quietRuntime({ log: logged.log });

let stop = async () => {};
afterEach(() => stop());

export type Form = Record<string, string> | [string, string][];

/** The modules every composition here holds, over this `tokens`, then `extra`. */
export const revocationModules = (tokens: Module, ...extra: Module[]): Module[] => [
	http,
	testServer(),
	tokens,
	issuerModule,
	clientsModule,
	secretHashModule,
	tokenRevocation,
	...extra,
];

/** Their configuration, reached at `origin`, with http's settings `peer` beside it. */
export const revocationConfig = (origin: string, peer: Partial<HttpSettings> = {}) => ({
	...kernelConfig(),
	...httpConfig({ "public-origin": origin, ...peer }),
	...issuerConfig({ url: origin }),
});

/**
 * token-revocation over the tokens stand-in. "app" and "other" are confidential, and "pub" is public.
 * `limit` sets the section and counts requests for real; otherwise nothing is limited.
 */
export async function serve(
	options: {
		revocable?: boolean;
		extra?: Module[];
		http?: Partial<HttpSettings>;
		limit?: Record<string, unknown>;
	} = {},
) {
	const down = unavailableSwitch<Tokens>("tokens");
	const recorded = auditStandIn();
	const stand = tokensStandIn({ revocable: options.revocable ?? true });
	const app = await assemble({
		modules: revocationModules(
			switchedModule(stand, accessTokens, down),
			recorded.module,
			...(options.limit ? [rateLimitModule, simulatedStore().module] : [rateLimitStandIn]),
			...(options.extra ?? []),
		),
		config: {
			...revocationConfig("https://issuer.example", options.http),
			...clientsConfig([
				confidentialClient({ id: "app" }),
				confidentialClient({ id: "other" }),
				publicClient({ id: "pub" }),
			]),
			...(options.limit ? { "token-revocation": options.limit } : {}),
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
		const res = await fetch(`${base}/oauth/revoke`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		const text = await res.text();
		const json = (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>;
		return { status: res.status, headers: res.headers, text, json, error: json.error };
	};
	// A token "app" holds for itself.
	const grant = {
		subject: "app",
		subjectKind: "client" as const,
		issuedTo: "app",
		audience: ["https://api"],
		scope: ["read"],
	};
	const issue = async () => {
		const issued = await issueAtOnce(app.get(accessTokenIssuance), {
			grant,
			grantType: "client_credentials",
		});
		if (issued.kind !== "issued") throw new Error(issued.reason);
		return issued.access.token;
	};
	const active = async (token: string) =>
		(await app.get(accessTokens).verifyAccess(token)).kind === "valid";
	/** The warnings logged since this composition was made. */
	const from = logged.lines().length;
	const warnings = () =>
		logged
			.lines()
			.slice(from)
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return { base, post, issue, active, down, events: recorded.events, warnings };
}
