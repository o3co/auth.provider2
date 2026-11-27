import { BlockList } from "node:net";
import { decodeReply, decodeRequest, encodeReply } from "@mod/front-core-codec";
import { fuzzer } from "@mod/front-core-codec/testing";
import { overHttp, type RequestKind, refusals, requests } from "@mod/front-core-wire";
import type { GuardedRoute, HttpResponse } from "@mod/http";
import type { Log } from "@mod/kernel";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { dispatcher } from "../src/dispatch.ts";

const kinds = Object.keys(requests) as RequestKind[];
const { validFrame } = fuzzer(20261127);
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
			{ numRuns: 2000, seed: 20261127 },
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
