import { type Approvals, approvals } from "@mod/approvals";
import { clientAssertion } from "@mod/client-assertion";
import { type Clients, clients } from "@mod/clients";
import { carriedOf, requestOf } from "@mod/front-core-codec";
import { requests } from "@mod/front-core-wire";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { requestsPerSource, sourceKey, type Window } from "@mod/rate-limit";
import { matches, redirects } from "@mod/redirect-uris";
import { itemsFromJar, jarClaims, type SigningKey } from "@mod/sdk-core-wire";
import {
	type CodeNeeds,
	codeNeedsIn,
	codeNeedsTakes,
	type StartUnmet,
} from "../code-needs/code-needs.ts";
import {
	jarReservations,
	type RequestClaims,
	type RequestSource,
	requestClaims,
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
	sha256,
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
	/** What a code needs, checked before T (internal module `code-needs`). */
	readonly needs: CodeNeeds;
	/** Why an OpenID request's `claims` is refused before T: the `requestClaims` contributed, else `claimsUnread`. */
	readonly claims: Pick<RequestClaims, "refusal">;
}

/** Where no module reads a request's `claims`, any is refused before T. */
export const claimsUnread: StartParts["claims"] = {
	refusal: (claims) => (claims === undefined ? undefined : "the claims parameter is not supported"),
};

/** A code's need unmet, as the start answers it before T. */
const unmetRefusal = (unmet: StartUnmet): Refusal => {
	switch (unmet.need) {
		case "grant":
			return { error: "invalid_request", description: "the client may not use the code grant" };
		case "resource":
			return {
				error: "invalid_target",
				description: unmet.description ?? "resource is not the audience asked",
			};
		case "challenge":
			return { error: "invalid_request_object", description: "code_challenge is malformed" };
		case "binding":
			return { error: "invalid_request_object", description: "dpop_jkt is out of its form" };
		default:
			return unmet satisfies never;
	}
};

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

/** The words `prompt` takes, each met by the person's tap at every login (D6); `none` is never met. */
const promptWords = new Set(["login", "consent", "select_account"]);

/** `prompt`, which is no item of T: refused where it asks no interaction, dropped where every tap meets it. */
function withoutPrompt(claims: Readonly<Record<string, unknown>>) {
	const { prompt, ...rest } = claims;
	if (prompt === undefined) return { claims: rest };
	const words = typeof prompt === "string" ? prompt.split(" ") : [];
	if (words.includes("none"))
		return {
			refused: { error: "login_required", description: "every login asks the person's passkey" },
		};
	if (words.length === 0 || words.some((w) => !promptWords.has(w)))
		return { refused: { error: "invalid_request", description: "prompt names a word not taken" } };
	return { claims: rest };
}

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
		const redirectUri = jar.claims.redirect_uri;
		const registered = client.section(redirects)["redirect-uris"];
		if (typeof redirectUri !== "string" || !registered.some((r) => matches(r, redirectUri)))
			return bad("the redirect URI is not one the client registered");
		const prompted = withoutPrompt(jar.claims);
		if ("refused" in prompted) return answerOf(400, prompted.refused as Refusal);
		const made = itemsFromJar(prompted.claims, sha256(jar.jar));
		if ("error" in made)
			return answerOf(400, { error: "invalid_request_object", description: made.error });
		const asksOpenid = p.needs.asksOpenid(made.items.scope);
		// Where no ID token is made, an OpenID request is refused before T, never once the person tapped.
		if (p.needs.openidUnmet(made.items))
			return answerOf(400, { error: "invalid_scope", description: "no ID token is issued" });
		// Its claims, read before T is made: one asked malformed, or without openid, is refused.
		const claimsRefused = p.claims.refusal(made.items.claims, asksOpenid);
		if (claimsRefused)
			return answerOf(400, { error: "invalid_request_object", description: claimsRefused });
		// What a code needs is checked here, before T, so the finish fails on none of it once the person tapped.
		const unmet = p.needs.atStart(client, made.items);
		if (unmet) return answerOf(400, unmetRefusal(unmet));
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

/** The authorization's items `authorize` fills: every one but `dpop_jkt`, which the sender binding's bridge fills. */
export const filledItems = {
	purpose: "authorization",
	names: [...jarClaims.items.filter((name) => name !== "dpop_jkt"), "jar_hash"],
	by: "authorize",
} as const;

/** What it publishes at the issuer's metadata, but the authorization endpoint, which is the screen's URL. */
export const issuerMetadata = Object.freeze({
	responseTypes: { name: "response_types_supported", value: ["code"] },
	responseModes: { name: "response_modes_supported", value: ["form_post"] },
	challengeMethods: { name: "code_challenge_methods_supported", value: ["S256"] },
	signedRequest: { name: "require_signed_request_object", value: true },
	requestParameter: { name: "request_parameter_supported", value: true },
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
	requestClaims,
	...codeNeedsTakes,
] as const;

/**
 * The route of ②, its parts taken from the composition, counted per source: the JAR's sources and
 * reservation, `approvals`, what a code needs. The answer to a person with no passkey and whether a
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
				sources: await c.collect(requestSources),
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
			needs: await codeNeedsIn(c, url),
			claims: (await c.collect(requestClaims))[0] ?? claimsUnread,
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
