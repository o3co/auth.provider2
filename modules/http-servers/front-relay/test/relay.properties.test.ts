import { validateHeaderValue } from "node:http";
import {
	type Carried,
	carriedOf,
	decodeRequest,
	encodeRequest,
	messageOf,
	operationAt,
	WireEncodeError,
	type WireReply,
} from "@mod/front-core-codec";
import { fuzzer } from "@mod/front-core-codec/testing";
import { overHttp, type RequestKind, requests } from "@mod/front-core-wire";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { CoreLink } from "../src/link.ts";
import { relayFallback } from "../src/relay.ts";

// C9: the Front's intake from the internet (an HTTP request the relay reads as an operation's message)
// and its answer of what the Core replies, each against a reading written apart from the relay.
const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261127) || 0;
const cases = Number(process.env.WIRE_FUZZ_CASES ?? 2000) || 2000;
const { int, pick, validFrame, randomBytes } = fuzzer(seed);
const kinds = Object.keys(requests) as RequestKind[];
const paths = [
	...new Set(kinds.map((k) => overHttp.operations[k].path)),
	"/",
	"/oauth/token/",
	"/x",
];

/** The refusal words in their wire order, and the status each answers, written out here apart from the wire. */
const words = [
	"invalid_request",
	"invalid_request_object",
	"invalid_client",
	"invalid_grant",
	"invalid_scope",
	"unsupported_grant_type",
	"access_denied",
	"invalid_dpop_proof",
	"use_dpop_nonce",
	"temporarily_unavailable",
	"server_error",
	"rate_limited",
	"too_many_attempts",
	"login_required",
	"invalid_request_uri",
	"invalid_target",
	"unauthorized_client",
] as const;
const statusOf: Record<string, number> = {
	invalid_client: 401,
	temporarily_unavailable: 503,
	server_error: 500,
	rate_limited: 429,
	too_many_attempts: 429,
};
/** The wire codes a rejection names, by number, written out here. */
const codeNames: Record<number, string> = {
	1: "version",
	2: "kind",
	3: "length",
	4: "truncated",
	5: "fieldLength",
	6: "fieldSyntax",
	7: "trailing",
	8: "enumRange",
};
const noStore = { "cache-control": "no-store", pragma: "no-cache" };

/** A log keeping every line at every level. */
function recording() {
	const lines: { level: string; event: string; fields: unknown }[] = [];
	const at =
		(level: string) =>
		(event: string, fields: unknown = {}) =>
			lines.push({ level, event, fields });
	const log = {
		debug: at("debug"),
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
	} as unknown as Log;
	return { lines, log };
}

/** A link to a Core that keeps each message sent, encoding it as the real one does, and replies, or fails, as told. */
function fakeLink(reply: WireReply | "unavailable") {
	const sent: { kind: RequestKind; message: unknown }[] = [];
	const link = {
		send: async (kind: RequestKind, message: unknown) => {
			encodeRequest(kind, 1, message as never);
			sent.push({ kind, message });
			if (reply === "unavailable") throw new Unavailable("the Core");
			return reply;
		},
		reach: async () => {},
		close: async () => {},
	} as unknown as CoreLink;
	return { link, sent };
}

const text = () =>
	int(2) === 0
		? pick([
				"",
				"x",
				"a".repeat(5000),
				"\ud800",
				"\u0000",
				"AA==",
				"17",
				"refresh_token",
				"client_credentials",
				"constructor",
			])
		: Array.from({ length: int(16) }, () => String.fromCharCode(32 + int(95))).join("");
/** A JSON member of no text: what puts a name among a body's mistyped. */
const notText = () => pick([1, 0, null, true, false, {}, [], ["a"], { a: "b" }] as unknown[]);

/**
 * An HTTP request as http-server hands it to the relay: a form, or a JSON object whose members of no
 * text are its mistyped (none on a form), its fields its strings; an operation's honest one, then
 * changed as a sender can. `pristine` where it is unchanged.
 */
function hostile() {
	const kind = pick(kinds);
	const decoded = decodeRequest(validFrame(kind));
	if (!decoded.ok) throw new Error("a valid frame");
	const carried = carriedOf(kind, decoded.value.message as never);
	const body = new Map<string, unknown[]>([...carried.values].map(([k, v]) => [k, [...v]]));
	const headers = new Map(carried.headers);
	let method = "POST";
	let path = overHttp.operations[kind].path;
	let json = overHttp.operations[kind].body === "json";
	let source = { address: "198.51.100.4", determined: int(2) === 0 };
	const changes = int(4) === 0 ? 0 : 1 + int(3);
	for (let k = changes; k > 0; k--) {
		const names = [...body.keys(), "source", "x", "grant_type"];
		switch (int(9)) {
			case 0:
				method = pick(["GET", "PUT", "post", "POST"]);
				break;
			case 1:
				path = pick(paths);
				break;
			case 2:
				json = !json;
				break;
			case 3:
				body.set(pick(names), [text(), text()]);
				break;
			case 4:
				body.set(pick(names), [text()]);
				break;
			case 5:
				body.delete(pick(names));
				break;
			case 6:
				// A member of no text: in a JSON body it is mistyped, in a form it is no value a form carries.
				body.set(pick(names), [notText()]);
				break;
			case 7:
				headers.set(pick(["dpop", "x-forwarded-for", "x-dpop", "content-type", "source"]), text());
				break;
			case 8:
				// The proxies' source: an address, one at the declared source's edge (45), one past it.
				source = {
					address: pick([
						"203.0.113.7",
						"::1",
						"10.0.0.1",
						"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
						"a".repeat(46),
					]),
					determined: int(2) === 0,
				};
				break;
		}
	}
	const request = json
		? testRequest({
				method,
				path,
				headers: new Map(headers),
				source,
				// One value a name: a JSON object; fieldsOf makes its strings the fields, the others mistyped.
				json: Object.fromEntries([...body].map(([k, v]) => [k, v[0] ?? ""])),
			})
		: testRequest({
				method,
				path,
				headers: new Map(headers),
				source,
				form: new Map(
					[...body].map(([k, v]) => [
						k,
						v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))),
					]),
				),
			});
	return {
		request,
		kind,
		message: decoded.value.message as Record<string, unknown>,
		pristine: changes === 0,
	};
}

/** A reply of any outcome the Core may send: each refusal word, and past the list; any code; nonces and retries at their edges. */
function anyReply(): WireReply | "unavailable" {
	switch (int(7)) {
		case 0:
		case 1:
			return {
				outcome: "ok",
				id: 1,
				message: {
					body: randomBytes(int(40)),
					dpopNonce: pick(["", "A".repeat(43), "A".repeat(64), "n0"]),
				},
			} as WireReply;
		case 2:
		case 3:
		case 4:
			return {
				outcome: "refused",
				id: 1,
				message: {
					error: pick([0, ...words.map((_, i) => i + 1), words.length + 1, 255, int(256)]),
					detail: pick(["", "used once", "é", "a".repeat(400)]),
					dpopNonce: pick(["", "n1", "A".repeat(64)]),
					retryAfter: pick([
						"",
						"7",
						"0",
						"007",
						"0000000000",
						"9999999999",
						"12345678901",
						"-1",
						"1.5",
						" 7",
						"1\n2",
					]),
				},
			} as WireReply;
		case 5:
			return {
				outcome: "rejected",
				id: 1,
				message: { code: pick([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, int(256)]) },
			} as WireReply;
		default:
			return "unavailable";
	}
}

type Expected = {
	readonly status: number;
	readonly headers: Record<string, string>;
	readonly json?: unknown;
	readonly body?: unknown;
	readonly sent: false | { readonly kind: RequestKind; readonly message: unknown };
	readonly why: string;
	readonly log?: unknown;
};

/** The answer the relay gives, read apart from it: the operation, the body's kind, the message read, the reply answered. */
function reference(request: HttpRequest, reply: WireReply | "unavailable"): Expected | "throws" {
	const kind = operationAt(request.method, request.path, request.fields);
	if (kind === undefined)
		return { status: 404, headers: noStore, body: undefined, sent: false, why: "notFound" };
	if ((request.json !== undefined) !== (overHttp.operations[kind].body === "json"))
		return { status: 415, headers: noStore, body: undefined, sent: false, why: "unsupported" };
	// The source the Front's trusted proxies determined alone; nothing the request names.
	const carried: Carried = {
		values: request.fields,
		headers: request.headers,
		mistyped: request.mistyped ?? new Set(),
		...(request.source.determined ? { source: request.source.address } : {}),
	};
	const bad = (field: string, code: string, why: string): Expected => ({
		status: 400,
		headers: noStore,
		json: { error: "invalid_request", error_description: `${field}: ${code}` },
		sent: false,
		why,
	});
	const read = messageOf(kind, carried);
	if (!read.ok) return bad(read.field, read.error, "unread");
	try {
		encodeRequest(kind, 1, read.message as never);
	} catch (error) {
		if (!(error instanceof WireEncodeError)) throw error;
		return bad(error.field, error.code, "unencoded");
	}
	const sent = { kind, message: read.message };
	if (reply === "unavailable") return "throws";
	switch (reply.outcome) {
		case "ok":
			return {
				status: kind === "par" ? 201 : 200,
				body: reply.message.body,
				headers: {
					...noStore,
					"content-type": "application/json",
					...(reply.message.dpopNonce === "" ? {} : { "dpop-nonce": reply.message.dpopNonce }),
				},
				sent,
				why: kind === "par" ? "created" : "ok",
			};
		case "refused": {
			const { error, detail, dpopNonce, retryAfter } = reply.message;
			const word = words[error - 1] ?? "server_error";
			return {
				status: statusOf[word] ?? 400,
				json: detail === "" ? { error: word } : { error: word, error_description: detail },
				headers: {
					...noStore,
					...(dpopNonce === "" ? {} : { "dpop-nonce": dpopNonce }),
					...(/^[0-9]{1,10}$/.test(retryAfter) ? { "retry-after": retryAfter } : {}),
				},
				sent,
				why: `word:${word}`,
			};
		}
		case "rejected":
			return {
				status: 502,
				headers: noStore,
				json: { error: "server_error" },
				sent,
				why: "rejected",
				log: [
					{
						level: "error",
						event: "front-relay.rejected",
						fields: { code: codeNames[reply.message.code] ?? "unknown" },
					},
				],
			};
	}
}

describe("the Front's relay of an HTTP request a sender makes", () => {
	it(
		"answers it as a reading written apart does: 404, 415 or 400 before anything is sent; else the message read, the source the proxies determined alone, and the Core's reply answered",
		async () => {
			const seen = new Map<string, number>();
			for (let i = 0; i < cases * 2; i++) {
				const drawn = hostile();
				const { request } = drawn;
				const reply = anyReply();
				const { link, sent } = fakeLink(reply);
				const { lines, log } = recording();
				const at = `case ${i} (seed ${seed}): ${request.method} ${request.path}`;
				const expected = reference(request, reply);
				const answering = relayFallback(link, log).answer(request);
				if (expected === "throws") {
					// The Core unreached: the failure is the server's to answer, never a reply made up here.
					await expect(answering, at).rejects.toSatisfy(isUnavailable);
					expect(sent.length, at).toBe(1);
					seen.set("unavailable", (seen.get("unavailable") ?? 0) + 1);
					continue;
				}
				const got = (await answering) as HttpResponse;
				seen.set(expected.why, (seen.get(expected.why) ?? 0) + 1);
				expect(got.status, at).toBe(expected.status);
				expect(got.headers, at).toEqual(expected.headers);
				if (expected.json !== undefined) expect(got.body, at).toEqual({ json: expected.json });
				else expect(got.body, at).toEqual(expected.body);
				// Nothing logged but a rejection, and that by its code's name alone.
				expect(lines, at).toEqual(expected.log ?? []);
				if (expected.sent === false) expect(sent, at).toEqual([]);
				else {
					expect(sent, at).toEqual([expected.sent]);
					const message = sent[0]?.message as Record<string, unknown>;
					// The declared source is the proxies' alone, on what was sent: empty where undetermined.
					if ("source" in message)
						expect(message.source, at).toBe(
							request.source.determined ? request.source.address : "",
						);
					// An honest request unchanged is sent as drawn, its source the proxies'.
					if (drawn.pristine) {
						expect(sent[0]?.kind, at).toBe(drawn.kind);
						expect(message, at).toEqual(
							"source" in drawn.message
								? {
										...drawn.message,
										source: request.source.determined ? request.source.address : "",
									}
								: drawn.message,
						);
					}
				}
				// An answer the server can write: each header a valid value.
				for (const [name, value] of Object.entries(got.headers ?? {}))
					for (const v of [value].flat())
						expect(() => validateHeaderValue(name, v), `${at} ${name}`).not.toThrow();
			}
			for (const why of [
				"notFound",
				"unsupported",
				"unread",
				"unencoded",
				"ok",
				"created",
				"rejected",
				"unavailable",
				...words.map((w) => `word:${w}`),
			])
				expect(seen.get(why) ?? 0, why).toBeGreaterThan(2);
		},
		Math.max(5000, cases * 6),
	);

	it("lets a page of another origin call the screen's operations alone, at their paths, by POST", () => {
		const fallback = relayFallback(fakeLink("unavailable").link, recording().log);
		const screen = new Set(
			kinds
				.filter((k) => overHttp.operations[k].crossOrigin)
				.map((k) => overHttp.operations[k].path),
		);
		for (const method of ["POST", "GET", "OPTIONS", "PUT", "post"])
			for (const path of paths) {
				const expected =
					method === "POST" && screen.has(path) ? { headers: ["content-type"] } : undefined;
				expect(fallback.cors?.(method, path), `${method} ${path}`).toEqual(expected);
			}
	});
});
