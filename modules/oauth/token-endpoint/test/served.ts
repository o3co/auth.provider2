import type { AuditEvent } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientEvents from "@mod/clients/audit-events";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { targetRules } from "@mod/grants";
import { listening } from "@mod/http";
import { assemble, defineModule, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { simulatedStore } from "@mod/store/testing";
import { afterEach, expect } from "vitest";
import declared from "../src/audit-events.ts";
import { basicOf, endpointConfig, endpointModules } from "./deployment.ts";

export const logged = recordingLog();
export const quiet = quietRuntime({
	log: logged.log,
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});
export const client = (
	id: string,
	method: string,
	extra: Record<string, unknown> = {},
	more: Record<string, unknown> = {},
) => {
	const sections = {
		...allowancesFor({
			grants: ["client_credentials"],
			scopes: ["read", "write"],
			"default-scopes": ["read"],
			...extra,
		}),
		...more,
	};
	return method === "none"
		? publicClient({ id, sections })
		: confidentialClient({ id, method, sections });
};

let stopServed = async () => {};
afterEach(() => stopServed());
/** Stops what the latest `serve` started; after each test, too. */
export const stop = () => stopServed();
/** The audit events of the latest `serve`. */
export let events: readonly AuditEvent[] = [];
// Every event a test records is one the module declares, with attributes it declares.
afterEach(() => {
	for (const { kind, attributes } of events) {
		const all: Readonly<Record<string, { readonly attributes: readonly string[] }>> = {
			...clientEvents,
			...declared,
		};
		const known: readonly string[] = all[kind]?.attributes ?? [];
		expect(known, `${kind} is declared`).not.toEqual([]);
		expect(
			Object.keys(attributes ?? {}).filter((name) => !known.includes(name)),
			kind,
		).toEqual([]);
	}
	events = [];
});

/** Clients allowed the test grants, registered only where a test composes those grants. */
export const echoClients = {
	echo: () => client("echo", "client_secret_basic", { grants: ["urn:test:echo"] }),
	pubecho: () => client("pubecho", "none", { grants: ["urn:test:echo"] }),
	echoes: () =>
		client("echoes", "client_secret_basic", { grants: ["urn:test:echo", "urn:test:other"] }),
};

/** The endpoint with `extra` modules and `clients` besides the usual, its `settings`, and http's `peer` settings. */
export async function serve(
	extra: Module[] = [],
	{
		settings = {},
		peer = {},
		clients = [],
	}: {
		settings?: object;
		peer?: Record<string, unknown>;
		clients?: ReturnType<typeof client>[];
	} = {},
) {
	const recorded = auditStandIn();
	events = recorded.events;
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			...extra,
		),
		config: {
			...endpointConfig({ peer: peer, issuer: "https://issuer.example" }),
			...clientsConfig([
				client("basic", "client_secret_basic", { audiences: ["https://api"] }),
				client("narrow", "client_secret_basic", { audiences: ["https://api", "https://two"] }),
				client("post", "client_secret_post"),
				client("pub", "none"),
				client("nogrant", "client_secret_basic", { grants: [] }),
				client("noscope", "client_secret_basic", { scopes: [], "default-scopes": [] }),
				client("emptydefault", "client_secret_basic", { "default-scopes": [] }),
				client("nodefault", "client_secret_basic", { "default-scopes": undefined }),
				...clients,
			]),
			"token-endpoint": settings,
		},
		runtime: quiet,
	});
	await app.start();
	stopServed = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const types = {
		form: "application/x-www-form-urlencoded",
		json: "application/json",
		text: "text/plain",
	};
	/** Posts `form` as client `id` (Basic, with its secret unless `secret` is given), as a body of type `as`. */
	const post = async (
		form: Record<string, unknown> | URLSearchParams,
		id?: string,
		{ secret = `${id}-secret`, as = "form" }: { secret?: string; as?: keyof typeof types } = {},
	) => {
		const headers: Record<string, string> = { "content-type": types[as] };
		if (id) headers.authorization = basicOf(id, secret);
		const body =
			as === "json" ? JSON.stringify(form) : String(new URLSearchParams(form as URLSearchParams));
		const res = await fetch(base, { method: "POST", headers, body });
		return {
			status: res.status,
			headers: res.headers,
			body: JSON.parse((await res.text()) || "{}") as Record<string, unknown>,
		};
	};
	return Object.assign(post, { url: base });
}

/**
 * A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do;
 * strict, it also refuses a `resource` sent to a grant that takes no audience.
 */
export const narrowing = (name = "narrowing", strict = false) =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(targetRules).by(() => ({
			...(strict
				? {
						untargeted: ({ param }: { param: (name: string) => string | undefined }) =>
							param("resource")
								? ({
										kind: "error",
										error: "invalid_target",
										description: "no resource here",
									} as const)
								: undefined,
						repeated: (name: string) =>
							name === "resource"
								? ({ kind: "error", error: "invalid_target", description: "one resource" } as const)
								: undefined,
					}
				: {}),
			target: ({ param, audience, within }) => {
				const asked = param("resource");
				if (!asked) return { kind: "audience", audience };
				return within(asked)
					? { kind: "audience", audience: [asked] }
					: { kind: "error", error: "invalid_target", description: `not ${asked}` };
			},
		})),
	]);
/** The claims of the access token in a success's body. */
export const claimsOf = (body: Record<string, unknown>) =>
	JSON.parse(Buffer.from(String(body.access_token).split(".")[1] ?? "", "base64url").toString());
export const audienceOf = (body: Record<string, unknown>) => claimsOf(body).aud;
