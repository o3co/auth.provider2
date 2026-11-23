import { carriedOf, type WireReply, type WireRequest } from "@mod/front-core-codec";
import { overHttp, refusals, replies } from "@mod/front-core-wire";
import {
	type GuardedRoute,
	type HttpRequest,
	type HttpResponse,
	jsonAnswer,
	type RequestEndObserver,
} from "@mod/http";
import { fieldsOf, readOnly, valuesOf } from "@mod/http/server";
import { type Clock, deepFreeze, isUnavailable, type Log } from "@mod/kernel";
import { type Source, sourceOf, type TrustedProxies } from "@mod/request-source";

type Word = (typeof refusals)[number];
/** A reply before its id is set. */
type Reply = {
	[O in WireReply["outcome"]]: Omit<Extract<WireReply, { outcome: O }>, "id">;
}[WireReply["outcome"]];

const encoder = new TextEncoder();
const okBodyMax = replies.ok[0].max;
const nonce = /^[A-Za-z0-9_-]{1,64}$/;
const detailMax = replies.refused[1].max;

const seconds = /^[0-9]{1,10}$/;

const refused = (word: Word, detail = "", dpopNonce = "", retryAfter = ""): Reply =>
	({
		outcome: "refused",
		message: { error: refusals.indexOf(word) + 1, detail, dpopNonce, retryAfter },
	}) as Reply;

/** A refusal's detail as the wire carries it: control characters as spaces, cut to the field's bytes at a character's edge. */
function detailOf(value: unknown): string {
	if (typeof value !== "string") return "";
	let text = "";
	let bytes = 0;
	for (const c of value) {
		const code = c.codePointAt(0) ?? 0;
		const shown = code < 0x20 || code === 0x7f ? " " : c;
		bytes += encoder.encode(shown).length;
		if (bytes > detailMax) break;
		text += shown;
	}
	return text;
}

/**
 * The route's answer as a reply: the operation's success status with JSON is `ok`; a JSON `error` the
 * wire names is that refusal, with its `Retry-After`; `503` is `temporarily_unavailable`; anything else
 * is `server_error`, warned of by the route and status alone.
 */
function replyOf(kind: WireRequest["kind"], response: HttpResponse, log: Log): Reply {
	const { path, successStatus } = overHttp.operations[kind];
	const sent = response.headers?.["dpop-nonce"] ?? "";
	const dpopNonce = nonce.test(sent) ? sent : "";
	const after = response.headers?.["retry-after"] ?? "";
	const retryAfter = seconds.test(after) ? after : "";
	const json =
		typeof response.body === "object" && "json" in response.body ? response.body.json : undefined;
	if (response.status === (successStatus ?? 200) && json !== undefined) {
		const body = encoder.encode(JSON.stringify(json));
		if (body.length <= okBodyMax) return { outcome: "ok", message: { body, dpopNonce } } as Reply;
	}
	const error = (json as { error?: unknown } | undefined)?.error;
	if (response.status >= 400 && refusals.includes(error as Word)) {
		return refused(
			error as Word,
			detailOf((json as { error_description?: unknown }).error_description),
			dpopNonce,
			retryAfter,
		);
	}
	if (response.status === 503) return refused("temporarily_unavailable", "", dpopNonce, retryAfter);
	log.warn("core-wire.unrelayable", { route: path, status: String(response.status) });
	return refused("server_error");
}

/** The request the operation's route reads, rebuilt from the frame: a form or a JSON object of strings, from the source given. */
function requestOf(request: WireRequest, source: Source): HttpRequest {
	const side = overHttp.operations[request.kind];
	const carried = carriedOf(request.kind, request.message as never);
	const values = valuesOf(carried.values);
	const empty = valuesOf(new Map());
	const body =
		side.body === "json"
			? (() => {
					const json = deepFreeze(Object.fromEntries([...values].map(([k, v]) => [k, v[0] ?? ""])));
					return { form: empty, json, ...fieldsOf(json) };
				})()
			: { form: values, fields: values };
	return Object.freeze({
		method: "POST",
		path: side.path,
		query: empty,
		headers: readOnly(new Map(carried.headers)),
		source,
		...body,
	});
}

/**
 * A frame's source: the one the Front declared, read as an `X-Forwarded-For` the Front sent, so the
 * Core's `http.trusted-proxies` names the Fronts and `http.proxy-hops` holds; `https`, as the Front
 * was reached. None declared leaves it the Front's, undetermined where the Front is trusted.
 */
export function declaredSource(proxies: TrustedProxies, peer: string, declared: string): Source {
	const headers = new Map(declared === "" ? [] : [["x-forwarded-for", declared]]);
	return Object.freeze({ ...sourceOf(proxies, peer, headers), scheme: "https" as const });
}

const bodyOf = (request: HttpRequest) => (request.json === undefined ? "form" : "json");

/** The route's answer, its policies first, as http's servers answer: Unavailable as the route declares, any other failure `500`. */
async function answered(
	route: GuardedRoute,
	request: HttpRequest,
	log: Log,
): Promise<HttpResponse> {
	try {
		const guarded = (await route.guard?.(request)) ?? "pass";
		if (guarded !== "pass") return guarded;
		// As http's servers do, a body the route does not take is refused after its policies saw it.
		if (!(route.takes ?? ["form"]).includes(bodyOf(request))) return { status: 415 };
		return await route.handle(request);
	} catch (error) {
		if (isUnavailable(error)) {
			let noted: Readonly<Record<string, string>> | undefined;
			try {
				noted = route.unavailable?.noted?.(request, error);
			} catch (failure) {
				log.error("http.failed", {
					kind: failure instanceof Error ? failure.name : typeof failure,
				});
			}
			log.warn("http.unavailable", { ...noted, what: error.what, route: route.path });
			return route.unavailable?.response ?? jsonAnswer(503, { error: "service_unavailable" });
		}
		log.error("http.failed", { kind: error instanceof Error ? error.name : typeof error });
		return { status: 500 };
	}
}

/**
 * Hands each frame to the route `overHttp` names for its operation, among the routes guarded at boot,
 * and makes the reply; each request's end is told to http's observers. An operation no route takes
 * is `server_error`, warned of by its kind.
 */
export function dispatcher(
	routes: readonly GuardedRoute[],
	proxies: TrustedProxies,
	ends: readonly RequestEndObserver[],
	log: Log,
	clock: Clock,
) {
	const byPath = new Map(routes.filter((r) => r.method === "POST").map((r) => [r.path, r]));
	return async (request: WireRequest, peer: string): Promise<WireReply> => {
		const source = declaredSource(proxies, peer, request.message.source);
		const started = clock.now();
		const path = overHttp.operations[request.kind].path;
		const route = byPath.get(path);
		let reply: Reply;
		let status = 404;
		if (!route) {
			log.warn("core-wire.no_route", { kind: request.kind });
			reply = refused("server_error");
		} else {
			const response = await answered(route, requestOf(request, source), log);
			status = response.status;
			reply = replyOf(request.kind, response, log);
		}
		const end = Object.freeze({
			method: "POST",
			...(route && { route: route.path }),
			status,
			ms: Math.max(0, clock.now() - started),
		});
		for (const observer of ends) {
			void Promise.resolve()
				.then(() => observer.ended(end))
				.catch(() => {});
		}
		return { ...reply, id: request.id } as WireReply;
	};
}
