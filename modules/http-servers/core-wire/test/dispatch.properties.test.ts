import { BlockList } from "node:net";
import {
	decodeReply,
	decodeRequest,
	encodeReply,
	encodeRequest,
	operationAt,
	requestOf,
	type WireRequest,
} from "@mod/front-core-codec";
import { fuzzer } from "@mod/front-core-codec/testing";
import { overHttp, type RequestKind, refusals, requests } from "@mod/front-core-wire";
import type { GuardedRoute, HttpRequest, HttpResponse } from "@mod/http";
import type { Log } from "@mod/kernel";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { dispatcher } from "../src/dispatch.ts";

const kinds = Object.keys(requests) as RequestKind[];
const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261127);
const cases = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
const { int, pick, validFrame, mutate } = fuzzer(seed);
const quiet: Log = { debug() {}, info() {}, warn() {}, error() {} } as unknown as Log;
const proxies = { trusted: new BlockList(), hops: 1 };
const clock = { now: () => 0 };

/** A text of the kinds a route might write: control characters, lone surrogates, pairs, long. */
const text = fc.oneof(
	fc.string({ unit: "binary", maxLength: 40 }),
	fc.constantFrom("\ud800", "x\udfffy", "😀", "\u0000\u007f", "é".repeat(300), "a".repeat(500)),
);
/** Any answer a route gives: its status, its JSON (an error the wire names or not), its headers. */
const answer = fc.record({
	status: fc.constantFrom(200, 201, 204, 302, 400, 401, 403, 429, 500, 503),
	json: fc.oneof(
		fc.record(
			{ error: fc.oneof(fc.constantFrom(...refusals), text), error_description: text },
			{ requiredKeys: [] },
		),
		fc.jsonValue(),
		fc.constant(undefined),
	),
	nonce: fc.oneof(fc.constant(undefined), text),
	after: fc.oneof(fc.constant(undefined), text, fc.constantFrom("7", "0", "99999999999")),
});

describe("the Core's reply to a frame", () => {
	it("encodes and is read back by the Front, whatever the route answers: its detail cleaned, a lone surrogate written as U+FFFD", async () => {
		await fc.assert(
			fc.asyncProperty(fc.constantFrom(...kinds), answer, async (kind, a) => {
				const response: HttpResponse = {
					status: a.status,
					...(a.json === undefined ? {} : { body: { json: a.json } }),
					headers: {
						...(a.nonce === undefined ? {} : { "dpop-nonce": a.nonce }),
						...(a.after === undefined ? {} : { "retry-after": a.after }),
					},
				};
				const route = {
					method: "POST",
					path: overHttp.operations[kind].path,
					takes: ["form", "json"],
					handle: async () => response,
				} as unknown as GuardedRoute;
				const decoded = decodeRequest(validFrame(kind));
				if (!decoded.ok) throw new Error("a valid frame");
				const reply = await dispatcher(
					[route],
					proxies,
					[],
					quiet,
					clock,
				)(decoded.value, "127.0.0.1");
				// The Core writes it, and the Front reads it back as it was.
				const read = decodeReply(encodeReply(reply));
				expect(read.ok && read.value).toEqual(reply);
			}),
			{ numRuns: cases, seed },
		);
	});

	it("writes a lone surrogate in a refusal's detail as U+FFFD, a pair kept", async () => {
		const route = {
			method: "POST",
			path: overHttp.operations.token.path,
			takes: ["form", "json"],
			handle: async () => ({
				status: 400,
				body: { json: { error: "invalid_request", error_description: "a\ud800b😀c\udfff" } },
			}),
		} as unknown as GuardedRoute;
		const decoded = decodeRequest(validFrame("token"));
		if (!decoded.ok) throw new Error("a valid frame");
		const reply = await dispatcher([route], proxies, [], quiet, clock)(decoded.value, "127.0.0.1");
		expect(reply.outcome === "refused" && reply.message.detail).toBe("a�b😀c�");
	});
});

// C9: the Core's rebuilding of a frame as the HTTP request its route reads (`dispatch.ts`'s requestOf).
describe("a frame handed to its route", () => {
	/** Routes at every operation's path, each keeping the request it was handed. */
	function capturing() {
		const handed: (HttpRequest & { readonly at: string })[] = [];
		const paths = [...new Set(kinds.map((k) => overHttp.operations[k].path))];
		const routes = paths.map(
			(path) =>
				({
					method: "POST",
					path,
					takes: ["form", "json"],
					handle: async (request: HttpRequest) => {
						// The route that ran keeps its own path, apart from the request's.
						handed.push(Object.assign(Object.create(request), { at: path }));
						return { status: 400, body: { json: { error: "invalid_request" } } };
					},
				}) as unknown as GuardedRoute,
		);
		return { handed, routes };
	}
	const trusting = (() => {
		const trusted = new BlockList();
		trusted.addAddress("127.0.0.1");
		return { trusted, hops: 1 };
	})();
	/** The source a route reads for a declared one, written apart from `declaredSource`: the Front (127.0.0.1) trusted, one hop. */
	const sources: readonly (readonly [string, string, boolean])[] = [
		["203.0.113.5", "203.0.113.5", true],
		["2001:db8::1", "2001:db8::1", true],
		["::ffff:198.51.100.7", "198.51.100.7", true],
		["198.51.100.1,203.0.113.7", "203.0.113.7", true],
		["garbage", "127.0.0.1", false],
		["", "127.0.0.1", false],
	];

	it(
		"hands every frame the Core takes, mutated ones among them, to its operation's route, rebuilt as the codec reads it back, from the source the Front declared",
		async () => {
			const { handed, routes } = capturing();
			const dispatch = dispatcher(routes, trusting, [], quiet, clock);
			const taken = new Map<RequestKind, number>();
			for (let i = 0; i < cases * 4; i++) {
				const kind = pick(kinds);
				const pristine = int(4) === 0;
				const decoded = decodeRequest(pristine ? validFrame(kind) : mutate(validFrame(kind)));
				if (!decoded.ok) continue;
				const [declared, address, determined] = pick(sources);
				const fields = decoded.value.message as Record<string, unknown>;
				// The declared source replaced by one of the table's, the frame still one the Core takes.
				const message = "source" in fields ? { ...fields, source: declared } : fields;
				const again = decodeRequest(encodeRequest(decoded.value.kind, 1, message as never));
				if (!again.ok) throw new Error(again.error);
				const request: WireRequest = again.value;
				handed.length = 0;
				await dispatch(request, "127.0.0.1");
				const got = handed[0];
				if (!got) throw new Error(`no route handed ${request.kind}`);
				if (!pristine) taken.set(request.kind, (taken.get(request.kind) ?? 0) + 1);
				const side = overHttp.operations[request.kind];
				expect(got.method).toBe("POST");
				expect(got.at, `${request.kind}: the route that ran`).toBe(side.path);
				expect(got.path).toBe(side.path);
				expect(got.query.size, request.kind).toBe(0);
				expect(got.json === undefined ? "form" : "json", request.kind).toBe(side.body);
				// The body itself as the route reads it: the form's values, or the JSON object of strings, as the fields.
				if (side.body === "form") expect([...got.form], request.kind).toEqual([...got.fields]);
				else {
					expect(got.form.size, request.kind).toBe(0);
					expect(got.json, request.kind).toEqual(
						Object.fromEntries([...got.fields].map(([k, v]) => [k, v[0]])),
					);
				}
				// The route reads the very operation, by its value where operations share a path.
				expect(operationAt("POST", got.path, got.fields), request.kind).toBe(request.kind);
				// Read back as the codec reads a request, the message as it came; the source read apart.
				const read = requestOf(request.kind, {
					values: got.fields,
					headers: got.headers,
					mistyped: got.mistyped ?? new Set(),
				});
				const expected = "source" in fields ? { ...request.message, source: "" } : request.message;
				expect(read, request.kind).toEqual({ ok: true, message: expected });
				if ("source" in fields)
					expect(got.source, declared).toMatchObject({ address, determined, scheme: "https" });
			}
			// Mutants the decoder took, apart from the valid frames: each kind more than twice.
			for (const kind of kinds) expect(taken.get(kind) ?? 0, kind).toBeGreaterThan(2);
		},
		Math.max(5000, cases * 10),
	);
});
