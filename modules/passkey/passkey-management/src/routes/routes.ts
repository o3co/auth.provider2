import { createHash } from "node:crypto";
import type { Screen } from "@mod/approvals";
import { continuations } from "@mod/continuation-wire";
import { type Read, requestOf } from "@mod/front-core-codec";
import { overHttp, type RequestKind } from "@mod/front-core-wire";
import { type HttpRequest, type HttpResponse, jsonAnswer, use } from "@mod/http";
import { requestsPerSource, sourceKey, type Window } from "@mod/rate-limit";
import type { Started as Approving, Finished } from "../approval/approval.ts";
import type { ContinueStage } from "../contract.ts";
import type { Registered } from "../registration/registration.ts";

/** The one refusal a route answers, whatever the reason, which its log alone tells. */
const denied = () => jsonAnswer(400, { error: "access_denied" });
const malformed = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });

/** A request's message as front-core-codec reads it, every field held to front-core-wire's spec; none for any other. */
function read<K extends RequestKind>(kind: K, request: HttpRequest) {
	const read: Read<K> = requestOf(kind, {
		values: request.fields,
		headers: new Map(),
		mistyped: request.mistyped ?? new Set(),
	});
	return read.ok ? read.message : undefined;
}

/** A field's bytes as the screen sent them, their one base64url text. */
const textOf = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** A wire enum's word for its number, as front-core-wire's texts give it; none for a number no text names. */
function wordOf(kind: RequestKind, name: string, n: number | undefined): string | undefined {
	const texts = overHttp.operations[kind].enumTexts?.[name]?.texts ?? {};
	return Object.entries(texts).find(([, value]) => value === n)?.[0];
}

const crossSite =
	"The screen's request reads no cookie: what it asks is bound to its sealed request and the screen's keys.";

/** A sealed continuation's ciphertext: its padded plaintext and the AEAD's tag, one length for every body. */
const sealedBytes = continuations.plainBytes + 16;

/** A continuation, its stage one `continuation-wire` names, its number never 0, clear or sealed as its stage is; none for any other. */
function continuationOf(request: HttpRequest) {
	const q = read("continue", request);
	const word = wordOf("continue", "stage", q?.stage);
	const stage = continuations.stages.find((name) => name === word);
	if (!q || !stage || q.seq === 0) return undefined;
	const { statement, seq, body, sig, enc, ct } = q;
	// A sealed stage's body and signature come in its sealing alone; any other's in the clear, unsealed.
	if ((continuations.sealed as readonly string[]).includes(stage)) {
		if (body !== "" || sig.length > 0 || enc.length !== 65 || ct.length !== sealedBytes)
			return undefined;
		return { stage, statement, seq, sealed: { enc: textOf(enc), ct: textOf(ct) } };
	}
	if (body === "" || sig.length !== 64 || enc.length > 0 || ct.length > 0) return undefined;
	return { stage, statement, seq, body, signature: textOf(sig) } as const;
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
 * wire's spec, a stage none continues refused, its answer of the form the wire gives its stage;
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
			const q = continuationOf(request);
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
				const q = read("keyFinish", request);
				if (!q) return malformed("a key's finish is its possession and the new key's assertion");
				return registeredBy(await p.finish({ statement: q.statement, assertion: q.assertion }));
			},
		},
	};
}

/** An approval's start: its purpose and the screen's keys; none for any other. */
function approvalStartOf(request: HttpRequest) {
	const q = read("approvalStart", request);
	const purpose = wordOf("approvalStart", "purpose", q?.purpose);
	if (!q || (purpose !== "passkey-add" && purpose !== "passkey-manage")) return undefined;
	const screen: Screen = {
		eEnc: textOf(q.eEnc),
		eSig: { kty: "EC", crv: "P-256", x: textOf(q.eSigX), y: textOf(q.eSigY) },
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
				const q = approvalStartOf(request);
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
				const q = read("approvalFinish", request);
				if (!q)
					return malformed(
						"an approval's finish is its statement and the approving key's assertion",
					);
				const finished = await p.finish({ statement: q.statement, assertion: q.assertion });
				return finished.kind === "completed"
					? jsonAnswer(200, { sealed: { enc: finished.enc, ct: finished.ct } })
					: denied();
			},
		},
	};
}
