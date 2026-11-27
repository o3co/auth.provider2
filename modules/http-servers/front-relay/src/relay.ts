import { messageOf, operationAt, WireEncodeError, type WireReply } from "@mod/front-core-codec";
import { overHttp, type RequestKind, refusals, wireErrors } from "@mod/front-core-wire";
import { type CorsRule, type HttpResponse, jsonAnswer, noStore, type Route } from "@mod/http";
import type { Fallback } from "@mod/http-server";
import type { Log } from "@mod/kernel";
import type { CoreLink } from "./link.ts";

const kinds = Object.keys(overHttp.operations) as RequestKind[];

/** Each path's cross-origin rule: the operations a page of another origin calls there. */
const corsByPath = new Map<string, CorsRule>(
	kinds.flatMap((kind) => {
		const { path, crossOrigin } = overHttp.operations[kind];
		return crossOrigin ? [[path, Object.freeze({ headers: crossOrigin.headers })] as const] : [];
	}),
);

const notFound: HttpResponse = Object.freeze({ status: 404, headers: noStore });
const unsupported: HttpResponse = Object.freeze({ status: 415, headers: noStore });
/** A field the frame cannot carry: `400`, the word its refusal carries (front-core-codec's one rule), the field and its code. */
const refused = (field: string, code: string, word: string) =>
	jsonAnswer(400, { error: word, error_description: `${field}: ${code}` });
const seconds = /^[0-9]{1,10}$/;
const codeName = (code: number) =>
	(Object.keys(wireErrors) as (keyof typeof wireErrors)[]).find((k) => wireErrors[k] === code) ??
	"unknown";

/** The Core's reply as the Front answers it: `ok` with the Core's body and the operation's success status, a refusal with its word's status, a frame the Core rejected `502`. */
function answerOf(kind: RequestKind, reply: WireReply, log: Log): HttpResponse {
	switch (reply.outcome) {
		case "ok": {
			const { body, dpopNonce } = reply.message;
			const headers = { ...noStore, "content-type": "application/json" };
			return {
				status: overHttp.operations[kind].successStatus ?? 200,
				headers: dpopNonce ? { ...headers, "dpop-nonce": dpopNonce } : headers,
				body,
			};
		}
		case "refused": {
			const { error, detail, dpopNonce, retryAfter } = reply.message;
			const word = refusals[error - 1] ?? "server_error";
			const json = detail ? { error: word, error_description: detail } : { error: word };
			const headers: Record<string, string> = {
				...(dpopNonce && { "dpop-nonce": dpopNonce }),
				...(seconds.test(retryAfter) && { "retry-after": retryAfter }),
			};
			return jsonAnswer(overHttp.statuses[word] ?? 400, json, { headers });
		}
		case "rejected":
			// An honest Front sends no frame the Core rejects: this one's encoder and the Core's disagree.
			log.error("front-relay.rejected", { code: codeName(reply.message.code) });
			return jsonAnswer(502, { error: "server_error" });
	}
}

/**
 * The Front's fallback: a request no route of the Front takes is the operation `overHttp` names at its
 * method, path and body, relayed to the Core as a frame, its reply answered as HTTP; any other is a
 * fixed `404`. A body of another type than the operation's is `415`, and a field the frame cannot
 * carry `400`, both before anything is sent.
 */
export function relayFallback(link: CoreLink, log: Log): Fallback {
	return {
		cors: (method, path) => (method === "POST" ? corsByPath.get(path) : undefined),
		answer: async (request) => {
			const kind = operationAt(request.method, request.path, request.fields);
			if (kind === undefined) return notFound;
			const json = request.json !== undefined;
			if (json !== (overHttp.operations[kind].body === "json")) return unsupported;
			// The source is the one the Front's trusted proxies determined, never one the request names.
			const { source } = request;
			const read = messageOf(kind, {
				values: request.fields,
				headers: request.headers,
				...(source.determined && { source: source.address }),
				mistyped: request.mistyped ?? new Set(),
			});
			if (!read.ok) return refused(read.field, read.error, read.word);
			try {
				return answerOf(kind, await link.send(kind, read.message), log);
			} catch (error) {
				if (error instanceof WireEncodeError) return refused(error.field, error.code, error.word);
				throw error;
			}
		},
	};
}

/** Whether a declared path reaches `path`: a middle `*` takes one non-empty segment, a last `/*` everything under it, as `http`'s `Route` says. */
function reaches(declared: string, path: string): boolean {
	const want = declared.split("/");
	const got = path.split("/");
	const under = declared.endsWith("/*");
	const fixed = under ? want.slice(0, -1) : want;
	if (under ? got.length < want.length : got.length !== want.length) return false;
	return fixed.every((segment, at) => (segment === "*" ? got[at] !== "" : segment === got[at]));
}

/** The Front's POST routes that take a path the Front relays: such a route answers there, and the relay is never reached. */
export function shadowing(routes: readonly Route[]): readonly Route[] {
	const paths = [...new Set(kinds.map((kind) => overHttp.operations[kind].path))];
	return routes.filter(
		(route) => route.method === "POST" && paths.some((path) => reaches(route.path, path)),
	);
}
