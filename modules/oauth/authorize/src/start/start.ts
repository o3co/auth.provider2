import { type Approvals, approvals } from "@mod/approvals";
import { clientAssertion } from "@mod/client-assertion";
import { type Clients, clients } from "@mod/clients";
import { carriedOf, requestOf } from "@mod/front-core-codec";
import { requests } from "@mod/front-core-wire";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { requestsPerSource, sourceKey, type Window } from "@mod/rate-limit";
import { jarClaims, type SigningKey } from "@mod/sdk-core-wire";
import {
	type AuthorizationRequests,
	authorizationRequests,
	jarReservations,
	type RequestSource,
	requestSources,
	type StartFields,
	type WithoutPasskey,
} from "../contract.ts";
import {
	type Jar,
	type JarParts,
	jarOf,
	type Refusal,
	reserving,
	type StartAnswer,
	startDigest,
} from "../jar/jar.ts";
import type { Settings } from "../section.ts";

export interface StartParts {
	readonly clients: Pick<Clients, "find">;
	readonly jar: JarParts;
	readonly reserve: (
		client: string,
		jar: Jar,
		digest: string,
		make: () => Promise<StartAnswer | { readonly refused: Refusal }>,
	) => Promise<StartAnswer | { readonly refused: Refusal }>;
	readonly approvals: Pick<Approvals, "issue">;
	/** The longest T, in characters, the way back takes: to the finish, and to a sign-up's continue where it may continue. */
	readonly fits: (signUp: boolean) => number;
	readonly withoutPasskey: WithoutPasskey | undefined;
	/**
	 * Whether a person with no passkey may sign up (F1): a module offers it (`signUpOffers`). Without,
	 * T allows no sign-up.
	 */
	readonly signUp: boolean;
	/** The request's check before T (internal module `request`). */
	readonly requests: AuthorizationRequests;
}

/** The statuses `front-core-wire` answers these refusals with; any other is 400. */
const statusOf: Readonly<Record<string, number>> = {
	invalid_client: 401,
	rate_limited: 429,
	temporarily_unavailable: 503,
};

/** `approvals`' refusal of the statement, as the start answers it. */
const issueRefusal = (reason: string): Refusal =>
	reason === "items"
		? { error: "invalid_request_object", description: "the request's items are refused" }
		: reason === "long"
			? {
					error: "invalid_request_object",
					description: "the request object makes a statement too long",
				}
			: reason === "limited"
				? { error: "rate_limited", description: "too many statements are being issued" }
				: { error: "temporarily_unavailable", description: `the statement was refused: ${reason}` };

const statementMax = (fields: readonly { readonly name: string; readonly max: number }[]) => {
	const max = fields.find((f) => f.name === "statement")?.max;
	if (max === undefined) throw new TypeError("authorize: its route contract names no statement");
	return max;
};
const finishMax = statementMax(requests.loginFinish.fields);
const continueMax = statementMax(requests.continue.fields);
/** The longest T its route contract (`front-core-wire`) carries back: to the finish, and to a sign-up's continue. */
export const tFits = (signUp: boolean) => (signUp ? Math.min(finishMax, continueMax) : finishMax);

const answerOf = (status: number, r: Refusal): HttpResponse =>
	jsonAnswer(status, { error: r.error, error_description: r.description });
const bad = (description: string) => answerOf(400, { error: "invalid_request", description });

/** ②: a login's start, from the screen's request and keys to the statement T it shows. */
export function starting(p: StartParts) {
	return async (request: HttpRequest): Promise<HttpResponse> => {
		// Every field held to front-core-wire's spec before any is acted on, as the Front's are.
		const sent = requestOf("loginStart", {
			values: request.fields,
			headers: new Map(),
			mistyped: request.mistyped ?? new Set(),
		});
		if (!sent.ok) return bad("the start's fields are not front-core-wire's");
		const { message } = sent;
		// Each field sent, by its name in front-core-wire, as the Front carries it: an empty one is not sent.
		const fields: StartFields = Object.fromEntries(
			[...carriedOf("loginStart", message).values].map(([name, [text]]) => [name, text ?? ""]),
		);
		// A request and a request_uri both sent: one form or the other, never both, whichever sources answer.
		if (fields.request !== undefined && fields.requestUri !== undefined)
			return bad("the start names a request or a request_uri, not both");
		// The spec holds the keys' lengths; an uncompressed P-256 point's first byte is this route's.
		if (message.eEnc[0] !== 4) return bad("the start names a client and the screen's two keys");
		// The keys as texts, each its bytes' one base64url spelling.
		const [eEnc, x, y] = [message.eEnc, message.eSigX, message.eSigY].map((bytes) =>
			Buffer.from(bytes).toString("base64url"),
		) as [string, string, string];
		const eSig: SigningKey = { kty: "EC", crv: "P-256", x, y };
		const clientId = message.clientId;
		const client = await p.clients.find(clientId);
		if (!client) return answerOf(401, { error: "invalid_client", description: "no such client" });
		const read = await jarOf(p.jar, fields, client);
		if ("refused" in read) return answerOf(statusOf[read.refused.error] ?? 400, read.refused);
		const { jar } = read;
		// The request checked before anything is reserved or signed; under PAR, T names this start's request_uri.
		const made = p.requests.check(client, jar, jar.jar, fields.requestUri);
		if ("refused" in made) return answerOf(400, made.refused);
		const answer = await p.reserve(client.id, jar, startDigest(jar.jar, eEnc, eSig), async () => {
			// Decided before T is signed, and kept on its record: the answer's `create` is only its copy.
			const create = (await p.withoutPasskey?.allows({ client, items: made.items })) ?? false;
			const issued = await p.approvals.issue({
				purpose: "authorization",
				items: made.items,
				screen: { eEnc, eSig },
				by: sourceKey(request.source.address),
				...(create && p.signUp ? { continues: ["sign-up"] as const } : {}),
				fits: p.fits(create && p.signUp),
			});
			if (issued.kind === "refused") return { refused: issueRefusal(issued.reason) };
			return { statement: issued.statement, challenge: issued.challenge, create };
		});
		if ("refused" in answer) return answerOf(statusOf[answer.refused.error] ?? 400, answer.refused);
		return jsonAnswer(200, answer);
	};
}

/** The items every T carries, which some module must declare it fills, or no start could be answered. */
const requiredItems = [...jarClaims.required, "jar_hash"];
/** The required items no declaration fills. */
export const unfilled = (
	declared: readonly { readonly purpose: string; readonly names: readonly string[] }[],
) =>
	requiredItems.filter(
		(name) => !declared.some((d) => d.purpose === "authorization" && d.names.includes(name)),
	);

/** The JAR sent by value, in the start's `request`: `authorize`'s own source. */
export const byValue: RequestSource = {
	name: "request",
	jarOf: async (fields) => (fields.request === undefined ? undefined : { jar: fields.request }),
};

/** The JAR sent by value where another source is the only one taken: refused, in its own words. */
const byValueRefused: RequestSource = {
	name: "request",
	jarOf: async (fields) =>
		fields.request === undefined
			? undefined
			: { refused: { error: "invalid_request", description: "a request by value is not taken" } },
};

/** The sources that say they are the only one taken. */
export const onlyOf = (sources: readonly RequestSource[]) => sources.filter((s) => s.only === true);

/** The sources taken: one saying it is the only one, alone, the JAR by value refused beside it; else every source. */
export const takenOf = (sources: readonly RequestSource[]): readonly RequestSource[] => {
	const only = onlyOf(sources);
	return only.length > 0 ? [...only, byValueRefused] : sources;
};

/** The authorization's items `authorize` fills: every one but `dpop_jkt`, which the sender binding's bridge fills; `request_uri` under PAR. */
export const filledItems = {
	purpose: "authorization",
	names: [...jarClaims.items.filter((name) => name !== "dpop_jkt"), "jar_hash", "request_uri"],
	by: "authorize",
} as const;

/** What it publishes at the issuer's metadata, but the authorization endpoint, which is the screen's URL. */
export const issuerMetadata = Object.freeze({
	responseTypes: { name: "response_types_supported", value: ["code"] },
	responseModes: { name: "response_modes_supported", value: ["form_post"] },
	challengeMethods: { name: "code_challenge_methods_supported", value: ["S256"] },
	signedRequest: { name: "require_signed_request_object", value: true },
	requestParameter: { name: "request_parameter_supported" },
	requestUriParameter: { name: "request_uri_parameter_supported" },
	issParameter: { name: "authorization_response_iss_parameter_supported", value: true },
});

/** What the start takes from the composition. */
export const startTakes = [
	clients,
	clientAssertion,
	approvals,
	issuer,
	jarReservations,
	requestSources,
	authorizationRequests,
] as const;

/**
 * The route of ②, its parts taken from the composition, counted per source: the JAR's sources and
 * reservation, `approvals`, the request's check. The answer to a person with no passkey and whether a
 * sign-up is offered come from the module, whose boot checks them.
 */
export async function startRouteIn(
	c: BuildContext<Settings>,
	p: { readonly withoutPasskey: WithoutPasskey | undefined; readonly signUp: boolean },
) {
	const url = (await c.get(issuer)).url;
	return startRoute(
		{
			clients: await c.get(clients),
			jar: {
				sources: takenOf(await c.collect(requestSources)),
				assertion: await c.get(clientAssertion),
				issuer: url,
				maxLifetimeS: c.section["jar-max-lifetime"],
				now: c.clock.now,
			},
			reserve: reserving({
				reservations: await c.get(jarReservations),
				skewS: c.section["clock-skew"],
				now: c.clock.now,
				token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
			}),
			approvals: await c.get(approvals),
			fits: tFits,
			withoutPasskey: p.withoutPasskey,
			signUp: p.signUp,
			requests: await c.get(authorizationRequests),
		},
		{ limit: c.section.requests, ms: c.section.window * 1000 },
	);
}

/** The route of ②: the screen's JSON, from any origin the Front relays it from, counted per source. */
export const startRoute = (p: StartParts, window: Window) => ({
	method: "POST" as const,
	path: "/login/start",
	uses: [use(requestsPerSource, { name: "authorize.start", window })],
	takes: ["json" as const],
	cors: { headers: ["content-type"] },
	crossSite:
		"The screen's request reads no cookie; what it starts is bound to the JAR its client signed and the screen's keys.",
	handle: starting(p),
});
