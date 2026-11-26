import { createHash } from "node:crypto";
import { continuations } from "@mod/continuation-wire";
import { requests } from "@mod/front-core-wire";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { Unavailable } from "@mod/kernel";
import { requestsPerSource, sourceKey, type Window } from "@mod/rate-limit";
import type { FirstKeyStage } from "@mod/sdk-core-wire";
import type { Started as Approving, Finished } from "../approval/approval.ts";
import type { ContinueStage } from "../contract.ts";
import type { Answered, Recovery } from "../mail-side/mail-side.ts";
import type { Nonces } from "../nonces/nonces.ts";
import type { Registered } from "../registration/registration.ts";
import type { Screen, SealedRequest } from "../sealed/sealed.ts";
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

/** A sealed continuation's ciphertext: its padded plaintext and the AEAD's tag, one length for every body. */
const sealedBytes = continuations.plainBytes + 16;

/** The most a field of a wire operation carries, as front-core-wire holds it: the route takes no more. */
const maxOf = (kind: "continue" | "keyFinish" | "approvalFinish", name: string) => {
	const field = (requests[kind].fields as readonly { name: string; max: number }[]).find(
		(f) => f.name === name,
	);
	if (field === undefined) throw new TypeError(`front-core-wire's ${kind} has no ${name}`);
	return field.max;
};
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

/** A continuation's fields as front-core-wire sizes them, its stage one `continuation-wire` names; none for any other. */
function continuationOf(fields: HttpRequest["fields"]) {
	const statement = jwsOf(fields.single("statement"), maxOf("continue", "statement"));
	const stage = continuations.stages.find((name) => name === fields.single("stage"));
	const seq = fields.single("seq");
	if (!statement || !stage) return undefined;
	if (seq === undefined || !/^[1-9][0-9]?$/.test(seq) || Number(seq) > 16) return undefined;
	const [body, sig, enc, ct] = ["body", "sig", "enc", "ct"].map(
		(name) => fields.single(name) ?? "",
	);
	// A sealed stage's body and signature come in its sealing alone; any other's in the clear, unsealed.
	if ((continuations.sealed as readonly string[]).includes(stage)) {
		if (body !== "" || sig !== "" || !bytesOf(enc, 65) || !bytesOf(ct, sealedBytes))
			return undefined;
		return { stage, statement, seq: Number(seq), sealed: { enc: enc as string, ct: ct as string } };
	}
	if (!utf8Of(body, maxOf("continue", "body")) || !bytesOf(sig, 64) || enc !== "" || ct !== "")
		return undefined;
	return {
		stage,
		statement,
		seq: Number(seq),
		body: body as string,
		signature: sig as string,
	} as const;
}

/** The stages contributed, by their word: boot refuses a stage two modules contribute. */
export function stagesOf(given: readonly ContinueStage[], refuse: (reason: string) => never) {
	const taken = new Map<string, ContinueStage>();
	for (const stage of given) {
		if (taken.has(stage.stage)) refuse(`two modules continue the stage ${stage.stage}`);
		taken.set(stage.stage, stage);
	}
	return taken as ReadonlyMap<string, ContinueStage>;
}

/** The answer's form a stage's continuation takes: a sealed value for a stage sealed, else a statement. */
const formOf = (stage: string) =>
	(continuations.sealed as readonly string[]).includes(stage) ? "sealed" : "statement";

/**
 * `POST /continue`, each stage handed to the module that continues it: the fields read by the
 * wire's sizes, a stage none continues refused, its answer of the form the wire gives its stage;
 * any refusal in one word, its reason to `refused` alone.
 */
export function continueRoute(p: {
	readonly stages: ReadonlyMap<string, ContinueStage>;
	readonly window: Window;
	readonly refused: (stage: string, reason: string) => void;
}) {
	return {
		method: "POST" as const,
		path: "/continue",
		uses: [use(requestsPerSource, { name: "passkey-management.continue", window: p.window })],
		takes: ["json" as const],
		cors: { headers: ["content-type"] },
		crossSite,
		handle: async (request: HttpRequest): Promise<HttpResponse> => {
			// A member of no string is none of the wire's fields, and one sent there is not the wire's.
			const q = request.mistyped?.size ? undefined : continuationOf(request.fields);
			if (!q)
				return malformed(
					"a continuation is a statement, a stage, a sequence number, and its body and E_sig's signature, sealed for a sealed stage",
				);
			const stage = p.stages.get(q.stage);
			if (!stage) return malformed("no module continues that stage here");
			const hash = createHash("sha256").update(q.statement).digest("base64url");
			const source = sourceKey(request.source.address);
			const answer = await stage.continue({ ...q, hash, source });
			if (answer.kind === "refused") {
				p.refused(q.stage, answer.reason);
				return denied();
			}
			if (answer.kind !== formOf(q.stage))
				throw new TypeError(`passkey-management: stage ${q.stage} answered another form`);
			return answer.kind === "statement"
				? jsonAnswer(200, { statement: answer.statement })
				: jsonAnswer(200, { sealed: { enc: answer.enc, ct: answer.ct } });
		},
	};
}

/** A registration's answer: the possession, or the completion sealed; any refusal in one word. */
function registeredBy(registered: Registered): HttpResponse {
	if (registered.kind === "possession") return jsonAnswer(200, { statement: registered.statement });
	if (registered.kind === "completed")
		return jsonAnswer(200, { sealed: { enc: registered.enc, ct: registered.ct } });
	return denied();
}

/** The route of a key's finish after its possession, counted per source, taking the screen's JSON across origins. */
export function keyRoutes(p: {
	readonly finish: (q: { statement: string; assertion: string }) => Promise<Registered>;
	readonly window: Window;
}) {
	const counted = (name: string) => [use(requestsPerSource, { name, window: p.window })];
	const screen = { takes: ["json" as const], cors: { headers: ["content-type"] }, crossSite };
	return {
		keyFinish: {
			method: "POST" as const,
			path: "/key/finish",
			uses: counted("passkey-management.key-finish"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				if (request.mistyped?.size)
					return malformed("a key's finish is its possession and the new key's assertion");
				const statement = jwsOf(
					request.fields.single("statement"),
					maxOf("keyFinish", "statement"),
				);
				const assertion = utf8Of(
					request.fields.single("assertion"),
					maxOf("keyFinish", "assertion"),
				);
				if (!statement || !assertion)
					return malformed("a key's finish is its possession and the new key's assertion");
				return registeredBy(await p.finish({ statement, assertion }));
			},
		},
	};
}

/** An approval's start's fields as front-core-wire sizes them; none for any other. */
function approvalStartOf(fields: HttpRequest["fields"]) {
	const purpose = fields.single("purpose");
	const eEnc = fields.single("eEnc");
	const x = fields.single("eSigX");
	const y = fields.single("eSigY");
	if (purpose !== "passkey-add" && purpose !== "passkey-manage") return undefined;
	if (!bytesOf(eEnc, 65) || !bytesOf(x, 32) || !bytesOf(y, 32)) return undefined;
	const screen: Screen = {
		eEnc: eEnc as string,
		eSig: { kty: "EC", crv: "P-256", x: x as string, y: y as string },
	};
	return { purpose, screen } as const;
}

/** The routes of a passkey-add's approval, each counted per source, taking the screen's JSON across origins. */
export function approvalRoutes(p: {
	readonly start: (q: {
		readonly purpose: "passkey-add" | "passkey-manage";
		readonly screen: Screen;
		readonly by: string;
	}) => Promise<Approving>;
	readonly finish: (q: { statement: string; assertion: string }) => Promise<Finished>;
	readonly window: Window;
}) {
	const counted = (name: string) => [use(requestsPerSource, { name, window: p.window })];
	const screen = { takes: ["json" as const], cors: { headers: ["content-type"] }, crossSite };
	return {
		approvalStart: {
			method: "POST" as const,
			path: "/approval/start",
			uses: counted("passkey-management.approval-start"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				const q = request.mistyped?.size ? undefined : approvalStartOf(request.fields);
				if (!q) return malformed("an approval's start is its purpose and the screen's keys");
				const started = await p.start({ ...q, by: sourceKey(request.source.address) });
				return started.kind === "statement"
					? jsonAnswer(200, { statement: started.statement })
					: denied();
			},
		},
		approvalFinish: {
			method: "POST" as const,
			path: "/approval/finish",
			uses: counted("passkey-management.approval-finish"),
			...screen,
			handle: async (request: HttpRequest): Promise<HttpResponse> => {
				if (request.mistyped?.size)
					return malformed(
						"an approval's finish is its statement and the approving key's assertion",
					);
				const statement = jwsOf(
					request.fields.single("statement"),
					maxOf("approvalFinish", "statement"),
				);
				const assertion = utf8Of(
					request.fields.single("assertion"),
					maxOf("approvalFinish", "assertion"),
				);
				if (!statement || !assertion)
					return malformed(
						"an approval's finish is its statement and the approving key's assertion",
					);
				const finished = await p.finish({ statement, assertion });
				return finished.kind === "completed"
					? jsonAnswer(200, { sealed: { enc: finished.enc, ct: finished.ct } })
					: denied();
			},
		},
	};
}
