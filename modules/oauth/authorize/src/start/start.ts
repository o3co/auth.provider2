import type { Approvals } from "@mod/approvals";
import { clientAllowance } from "@mod/client-allowance";
import type { Clients } from "@mod/clients";
import { challengeShape, codeGrantType } from "@mod/code-grant";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { requestsPerSource, sourceKey, type Window } from "@mod/rate-limit";
import { matches, redirects } from "@mod/redirect-uris";
import { itemsFromJar, jarClaims, type SigningKey } from "@mod/sdk-core-wire";
import { type SenderBindings, senderBinding } from "@mod/sender-binding";
import type { RequestSource, StartFields, WithoutPasskey } from "../contract.ts";
import {
	type Jar,
	type JarParts,
	jarOf,
	type Refusal,
	type StartAnswer,
	sha256,
	startDigest,
} from "../jar/jar.ts";

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
	readonly withoutPasskey: WithoutPasskey | undefined;
	readonly bindings: Pick<SenderBindings, "requestedOf">;
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
		: reason === "limited"
			? { error: "rate_limited", description: "too many statements are being issued" }
			: { error: "temporarily_unavailable", description: `the statement was refused: ${reason}` };

const answerOf = (status: number, r: Refusal): HttpResponse =>
	jsonAnswer(status, { error: r.error, error_description: r.description });
const bad = (description: string) => answerOf(400, { error: "invalid_request", description });

/** A P-256 point, uncompressed (65 bytes, 0x04 first), unpadded base64url; none for anything else. */
const pointOf = (text: string | undefined) =>
	bytesOf(text, 65) !== undefined && Buffer.from(text as string, "base64url")[0] === 4
		? text
		: undefined;

/** Bytes of a given length, unpadded base64url; none for anything else. */
const bytesOf = (text: string | undefined, length: number) =>
	text !== undefined &&
	/^[A-Za-z0-9_-]+$/.test(text) &&
	Buffer.from(text, "base64url").length === length
		? text
		: undefined;

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
		const fields: StartFields = Object.fromEntries(
			Object.entries(request.json ?? {}).filter(([, v]) => typeof v === "string"),
		) as StartFields;
		const eEnc = pointOf(fields.eEnc);
		const x = bytesOf(fields.eSigX, 32);
		const y = bytesOf(fields.eSigY, 32);
		if (fields.clientId === undefined || !eEnc || !x || !y)
			return bad("the start names a client and the screen's two keys");
		const eSig: SigningKey = { kty: "EC", crv: "P-256", x, y };
		const client = await p.clients.find(fields.clientId);
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
		// No ID token is issued yet: an OpenID request, or one asking claims, is refused before T is made.
		if (!("error" in made) && made.items.scope.split(" ").includes("openid"))
			return answerOf(400, { error: "invalid_scope", description: "openid is not taken" });
		if (!("error" in made) && made.items.claims !== undefined)
			return answerOf(400, {
				error: "invalid_request_object",
				description: "claims are not taken",
			});
		if ("error" in made)
			return answerOf(400, { error: "invalid_request_object", description: made.error });
		// What a code needs is checked here, before T, so the finish fails on none of it once the person tapped.
		if (!clientAllowance.allowsGrant(client, codeGrantType))
			return answerOf(400, {
				error: "invalid_request",
				description: "the client may not use the code grant",
			});
		if (!challengeShape.test(made.items.code_challenge))
			return answerOf(400, {
				error: "invalid_request_object",
				description: "code_challenge is malformed",
			});
		const bound = p.bindings.requestedOf((name) =>
			name === "dpop_jkt" ? made.items.dpop_jkt : undefined,
		);
		if (bound.kind !== "requested")
			return answerOf(400, {
				error: "invalid_request_object",
				description: "dpop_jkt is out of its form",
			});
		const answer = await p.reserve(client.id, jar, startDigest(jar.jar, eEnc, eSig), async () => {
			const issued = await p.approvals.issue({
				purpose: "authorization",
				items: made.items,
				screen: { eEnc, eSig },
				by: sourceKey(request.source.address),
			});
			if (issued.kind === "refused") return { refused: issueRefusal(issued.reason) };
			const create = (await p.withoutPasskey?.allows({ client, items: made.items })) ?? false;
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

/** The binding kinds' reading of what a request asks for ahead, taken from the composition. */
export const bindingsIn = (c: Pick<BuildContext<unknown>, "get">) => c.get(senderBinding);

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
