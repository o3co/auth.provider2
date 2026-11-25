import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import type { FirstKeyStage } from "@mod/sdk-core-wire";
import type { Answered, Recovery } from "../mail-side/mail-side.ts";
import type { Nonces } from "../nonces/nonces.ts";
import type { Continuation, Registered } from "../registration/registration.ts";
import type { SealedRequest } from "../sealed/sealed.ts";
import type { Started } from "../start/start.ts";

/** The one refusal a first key's path answers, whatever the reason, which its log alone tells. */
const denied = () => jsonAnswer(400, { error: "access_denied" });
const malformed = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });

/** A field's bytes from its unpadded base64url, of a length within the wire's bounds; none for any other. */
function bytesOf(text: string | undefined, min: number, max = min): Uint8Array | undefined {
	if (text === undefined || !/^[A-Za-z0-9_-]*$/.test(text)) return undefined;
	const bytes = Buffer.from(text, "base64url");
	// One spelling alone: a text that does not read back as given names no bytes.
	if (bytes.toString("base64url") !== text) return undefined;
	return bytes.length >= min && bytes.length <= max ? new Uint8Array(bytes) : undefined;
}

/** A sealed request's fields as front-core-wire sizes them; none where one is missing or of another size. */
function sealedOf(fields: HttpRequest["fields"]): SealedRequest | undefined {
	const nonce = fields.single("nonce");
	const eEnc = bytesOf(fields.single("eEnc"), 65);
	const eSigX = bytesOf(fields.single("eSigX"), 32);
	const eSigY = bytesOf(fields.single("eSigY"), 32);
	const enc = bytesOf(fields.single("enc"), 65);
	const ct = bytesOf(fields.single("ct"), 17, 2048);
	if (nonce === undefined || !bytesOf(nonce, 32) || !eEnc || !eSigX || !eSigY || !enc || !ct)
		return undefined;
	return { nonce, eEnc, eSigX, eSigY, enc, ct };
}

const stages = new Set<string>(["start", "mail"]);
const crossSite =
	"The screen's request reads no cookie: what it asks is bound to its sealed request and the screen's keys.";

/** A recovery's fields as front-core-wire sizes them; none where one is missing or of another size. */
function recoveryOf(fields: HttpRequest["fields"]): Recovery | undefined {
	const nonce = fields.single("nonce");
	const digest = fields.single("digest");
	const sig = fields.single("sig");
	if (nonce === undefined || !bytesOf(nonce, 32) || digest === undefined || !bytesOf(digest, 32))
		return undefined;
	return sig !== undefined && bytesOf(sig, 64) ? { nonce, digest, sig } : undefined;
}

/** The mail's side's answer: its statement, the path's refusal in one word, the opening withdrawn unavailable. */
function answeredBy(answered: Answered): HttpResponse {
	if (answered.kind === "answered") return jsonAnswer(200, { statement: answered.statement });
	if (answered.kind === "refused") return denied();
	// A statement's own refusal, or the opening withdrawn: unavailable, as a store that cannot tell.
	throw new Unavailable("passkey-management");
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
			uses: counted("passkey-management.nonce"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const stage = request.fields.single("stage");
				if (stage === undefined || !stages.has(stage))
					return malformed("the stage is start or mail");
				return jsonAnswer(200, { nonce: await p.nonces.issue(stage as FirstKeyStage) });
			},
		},
		start: {
			method: "POST" as const,
			path: "/first-key/start",
			uses: counted("passkey-management.start"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const sealed = sealedOf(request.fields);
				if (!sealed) return malformed("the start is a nonce, the screen's keys and a sealing");
				const started = await p.start(sealed);
				if (started.kind === "answered") return jsonAnswer(200, { sealed: started.sealed });
				// The keys' holder no longer lets this Core open: unavailable, as a store that cannot tell.
				if (started.kind === "withdrawn") throw new Unavailable("passkey-management");
				return denied();
			},
		},
		mail: {
			method: "POST" as const,
			path: "/first-key/mail",
			uses: counted("passkey-management.mail"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const sealed = sealedOf(request.fields);
				if (!sealed)
					return malformed("the mail's side is a nonce, the screen's keys and a sealing");
				return answeredBy(await p.mail(sealed));
			},
		},
		recover: {
			method: "POST" as const,
			path: "/first-key/recover",
			uses: counted("passkey-management.recover"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const recovery = recoveryOf(request.fields);
				if (!recovery)
					return malformed(
						"a recovery is the mail's nonce, its request's digest and E_sig's signature",
					);
				return answeredBy(await p.recover(recovery));
			},
		},
	};
}

/** A compact JWS of at most `max` characters; none for any other text. */
const jwsOf = (text: string | undefined, max: number) =>
	text !== undefined &&
	text.length <= max &&
	/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)
		? text
		: undefined;
/** A UTF-8 text of 1 to `max` bytes; none for any other. */
const utf8Of = (text: string | undefined, max: number) =>
	text !== undefined && text.length > 0 && Buffer.byteLength(text) <= max ? text : undefined;

/** A continuation's fields as front-core-wire sizes them, its stage `register`; none for any other. */
function continuationOf(fields: HttpRequest["fields"]): Continuation | "stage" | undefined {
	const statement = jwsOf(fields.single("statement"), 8192);
	const seq = fields.single("seq");
	const body = utf8Of(fields.single("body"), 8192);
	const sig = fields.single("sig");
	if (!statement || !body || sig === undefined || !bytesOf(sig, 64)) return undefined;
	if (seq === undefined || !/^[1-9][0-9]?$/.test(seq) || Number(seq) > 16) return undefined;
	// A key's deletion and renaming are passkey-manage's, which this route does not take.
	if (fields.single("stage") !== "register") return "stage";
	// A register's body is sent as it is, signed in the clear: no sealing comes with it.
	if ((fields.single("enc") ?? "") !== "" || (fields.single("ct") ?? "") !== "") return undefined;
	return { statement, seq: Number(seq), body, sig };
}

/** A registration's answer: the possession, or the completion sealed; any refusal in one word. */
function registeredBy(registered: Registered): HttpResponse {
	if (registered.kind === "possession") return jsonAnswer(200, { statement: registered.statement });
	if (registered.kind === "completed")
		return jsonAnswer(200, { sealed: { enc: registered.enc, ct: registered.ct } });
	return denied();
}

/** The routes of a key's registration after its creation, each counted per source, taking the screen's JSON across origins. */
export function keyRoutes(p: {
	readonly register: (q: Continuation) => Promise<Registered>;
	readonly finish: (q: { statement: string; assertion: string }) => Promise<Registered>;
	readonly window: Window;
}) {
	const counted = (name: string) => [use(requestsPerSource, { name, window: p.window })];
	const screen = { takes: ["json" as const], cors: { headers: ["content-type"] }, crossSite };
	return {
		continue: {
			method: "POST" as const,
			path: "/continue",
			uses: counted("passkey-management.continue"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				// A member of no string is none of the wire's fields, and one sent there is not the wire's.
				const q = request.mistyped?.size ? undefined : continuationOf(request.fields);
				if (q === "stage") return malformed("the stage continued here is register");
				if (!q)
					return malformed(
						"a continuation is a statement, a stage, a sequence number, a body and E_sig's signature",
					);
				return registeredBy(await p.register(q));
			},
		},
		keyFinish: {
			method: "POST" as const,
			path: "/key/finish",
			uses: counted("passkey-management.key-finish"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				if (request.mistyped?.size)
					return malformed("a key's finish is its possession and the new key's assertion");
				const statement = jwsOf(request.fields.single("statement"), 4096);
				const assertion = utf8Of(request.fields.single("assertion"), 8192);
				if (!statement || !assertion)
					return malformed("a key's finish is its possession and the new key's assertion");
				return registeredBy(await p.finish({ statement, assertion }));
			},
		},
	};
}
