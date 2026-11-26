import type { Read } from "@mod/front-core-codec";
import { requestOf } from "@mod/front-core-codec";
import type { RequestKind } from "@mod/front-core-wire";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import type { FirstKeyStage } from "@mod/sdk-core-wire";
import type { Answered, Recovery } from "../mail-side/mail-side.ts";
import type { Nonces } from "../nonces/nonces.ts";
import type { SealedRequest } from "../sealed/sealed.ts";
import type { Started } from "../start/start.ts";

/** The one refusal a first key's path answers, whatever the reason, which its log alone tells. */
const denied = () => jsonAnswer(400, { error: "access_denied" });
const malformed = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });

const crossSite =
	"The screen's request reads no cookie: what it asks is bound to its sealed request and the screen's keys.";

/** A request's message as front-core-codec reads it, every field held to front-core-wire's spec; none for any other. */
function read<K extends RequestKind>(kind: K, request: HttpRequest) {
	const read: Read<K> = requestOf(kind, {
		values: request.fields,
		headers: new Map(),
		mistyped: request.mistyped ?? new Set(),
	});
	return read.ok ? read.message : undefined;
}

/** The stages a nonce is given for, by the number front-core-wire's enum reads them as. */
const stages: readonly FirstKeyStage[] = ["start", "mail"];

/** The mail's side's answer: its statement, the path's refusal in one word, the opening withdrawn unavailable. */
function answeredBy(answered: Answered): HttpResponse {
	if (answered.kind === "answered") return jsonAnswer(200, { statement: answered.statement });
	if (answered.kind === "refused") return denied();
	// The opening withdrawn: unavailable, as a store that cannot tell.
	throw new Unavailable("first-key");
}

/** The routes of a first key's path, each counted per source, taking the screen's JSON across origins. */
export function firstKeyRoutes(p: {
	readonly nonces: Nonces;
	readonly start: (request: SealedRequest) => Promise<Started>;
	readonly mail: (request: SealedRequest) => Promise<Answered>;
	readonly recover: (recovery: Recovery) => Promise<Answered>;
	readonly window: Window;
}) {
	const counted = (name: string) => [use(requestsPerSource, { name, window: p.window })];
	const screen = { takes: ["json" as const], cors: { headers: ["content-type"] }, crossSite };
	return {
		nonce: {
			method: "POST" as const,
			path: "/first-key/nonce",
			uses: counted("first-key.nonce"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const stage = stages[read("firstKeyNonce", request)?.stage ?? -1];
				if (stage === undefined) return malformed("the stage is start or mail");
				return jsonAnswer(200, { nonce: await p.nonces.issue(stage) });
			},
		},
		start: {
			method: "POST" as const,
			path: "/first-key/start",
			uses: counted("first-key.start"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const sealed = read("firstKeyStart", request);
				if (!sealed) return malformed("the start is a nonce, the screen's keys and a sealing");
				const started = await p.start(sealed);
				if (started.kind === "answered") return jsonAnswer(200, { sealed: started.sealed });
				// The keys' holder no longer lets this Core open: unavailable, as a store that cannot tell.
				if (started.kind === "withdrawn") throw new Unavailable("first-key");
				return denied();
			},
		},
		mail: {
			method: "POST" as const,
			path: "/first-key/mail",
			uses: counted("first-key.mail"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const sealed = read("firstKeyMail", request);
				if (!sealed)
					return malformed("the mail's side is a nonce, the screen's keys and a sealing");
				return answeredBy(await p.mail(sealed));
			},
		},
		recover: {
			method: "POST" as const,
			path: "/first-key/recover",
			uses: counted("first-key.recover"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const recovery = read("firstKeyRecover", request);
				if (!recovery)
					return malformed(
						"a recovery is the mail's nonce, its request's digest and E_sig's signature",
					);
				const { nonce, digest } = recovery;
				const sig = Buffer.from(recovery.sig).toString("base64url");
				return answeredBy(await p.recover({ nonce, digest, sig }));
			},
		},
	};
}
