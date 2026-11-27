import { describe, expect, it } from "vitest";
import { ledger } from "../../deviations/deviations.ts";
import { readingOf } from "../../words/words.ts";
import { type Expected, expectedFor, expectedOf, expectedProblems } from "../expected.ts";

const keys = ["jar-typ-required", "jar-required"];
const variant = { openid: "openid_connect", sender_constrain: "dpop" };
const typ = {
	block: "Make request to PAR endpoint",
	refuser: "core",
	place: "par",
	status: 400,
	error: "invalid_request_object",
	description: "not of the typ asked",
	reading: "observed",
	keys: ["jar-typ-required"],
} as const;
const own = {
	...typ,
	error: "invalid_request",
	description: "request: fieldLength",
	refuser: "front",
	reading: "own",
	keys: undefined,
};
const failure = { src: "CheckPAREndpointResponse201WithNoError", keys: ["jar-typ-required"] };
const entry = (over: Partial<Record<keyof Expected, unknown>> = {}) => ({
	test: "fapi2-security-profile-final-happy-flow",
	variant,
	result: "FAILED",
	reading: "explained",
	refusals: [typ],
	failures: [failure],
	...over,
});

describe("expected results", () => {
	it("takes entries whose every key the ledger has, each reading with its result and the parts that say it", () => {
		const taken = [
			entry(),
			entry({ test: "negative", result: "PASSED", reading: "before-wall", failures: undefined }),
			entry({
				test: "own",
				result: "PASSED",
				reading: "own-condition",
				refusals: [own],
				failures: undefined,
			}),
			// A refusal of no body (a 404) is its status alone.
			entry({
				test: "verb",
				result: "PASSED",
				reading: "own-condition",
				refusals: [{ ...own, error: undefined, description: undefined, status: 404 }],
				failures: undefined,
			}),
			entry({
				test: "skipped",
				result: "SKIPPED",
				reading: "skipped",
				refusals: [],
				failures: undefined,
			}),
			entry({ test: "warned", result: "WARNING", failures: undefined, warnings: [failure] }),
			// Words the table cannot tell apart, a review so read: unapproved, failing no run.
			entry({
				test: "review",
				result: "REVIEW",
				reading: "unconfirmed",
				refusals: [{ ...typ, place: "start", reading: "unconfirmed", keys: ["jar-required"] }],
				failures: undefined,
			}),
			// Mixed blocks: the module explained, a block's refusal unconfirmed beside it.
			entry({
				test: "mixed",
				refusals: [{ ...typ, reading: "unconfirmed", keys: undefined }, typ],
			}),
		];
		expect(expectedProblems(taken, keys)).toEqual([]);
		expect(expectedOf(JSON.stringify(taken), keys)).toHaveLength(8);
	});

	it("refuses, before the suite starts, plan §6's: a key not in the ledger, a key twice, an empty field, a wildcard, an entry twice, a variant that is no object", () => {
		const cases: [unknown, string][] = [
			[[entry({ refusals: [{ ...typ, keys: ["no-such-row"] }] })], "which the ledger has not"],
			[
				[entry({ failures: [{ ...failure, keys: ["jar-typ-required", "jar-typ-required"] }] })],
				"twice",
			],
			[[entry({ refusals: [{ ...typ, description: "" }] })], "empty description"],
			[[entry({ refusals: [{ ...typ, keys: [] }] })], "names no key"],
			[[entry({ test: "" })], "names no test"],
			[[entry({ test: "fapi2-*" })], "test is a wildcard"],
			[[entry({ refusals: [{ ...typ, description: "not of *" }] })], "description is a wildcard"],
			[[entry(), entry()], "under its variant again"],
			[[entry({ variant: ["openid_connect"] })], "variant is no object"],
			[[entry({ variant: {} })], "variant is no object"],
			[[entry({ variant: { openid: 1 } })], "variant is no object"],
			[[entry({ variant: { "": "openid_connect" } })], "variant is no object"],
			[[entry({ variant: { openid: "*" } })], "variant is no object"],
			[{}, "a list of entries"],
		];
		for (const [value, said] of cases)
			expect(expectedProblems(value, keys).join("\n"), said).toContain(said);
		// The same module under another variant is another entry; a `?` is no wildcard.
		expect(
			expectedProblems([entry(), entry({ variant: { openid: "plain_oauth" } })], keys),
		).toEqual([]);
		expect(
			expectedProblems([entry({ refusals: [{ ...typ, block: "Call ?dummy1=lorem" }] })], keys),
		).toEqual([]);
		expect(() => expectedOf(JSON.stringify([entry({ test: "*" })]), keys)).toThrow(/wildcard/);
	});

	it("refuses a reading with a result it may not have, or without the parts that say it", () => {
		const cases: [unknown, string][] = [
			[[entry({ reading: "passed" })], "is passed, which a FAILED is not"],
			[[entry({ result: "PASSED", failures: undefined })], "is explained, which a PASSED is not"],
			[[entry({ reading: "before-wall" })], "is before-wall, which a FAILED is not"],
			[[entry({ reading: "own-condition" })], "is own-condition, which a FAILED is not"],
			[
				[entry({ result: "SKIPPED", reading: "passed", failures: undefined })],
				"is passed, which a SKIPPED is not",
			],
			[[entry({ result: "WARNING", failures: undefined })], "warned by no condition"],
			[[entry({ failures: undefined })], "failed by no condition"],
			[[entry({ result: "REVIEW" })], "names failures, yet does not fail"],
			[
				[entry({ refusals: [{ ...typ, reading: "own", keys: undefined }] })],
				"explained by no cause observed",
			],
			[[entry({ failures: [{ src: failure.src }] })], "a condition names no key"],
			[
				[entry({ result: "PASSED", reading: "own-condition", refusals: [], failures: undefined })],
				"by no refusal of it",
			],
			[
				[entry({ result: "PASSED", reading: "before-wall", refusals: [own], failures: undefined })],
				"by no cause observed",
			],
			[
				[entry({ result: "REVIEW", reading: "unconfirmed", failures: undefined })],
				"by nothing the words leave apart",
			],
			[
				[entry({ reading: "skipped", result: "SKIPPED", failures: undefined })],
				"is skipped, yet meets a refusal",
			],
			[
				[entry({ refusals: [{ ...typ, keys: ["jar-typ-required", "jar-required"] }] })],
				"is observed, of one row",
			],
			[
				[entry({ refusals: [{ ...own, keys: ["jar-typ-required"] }] })],
				"is the test's own, yet names a key",
			],
			[
				[entry({ refusals: [{ ...typ, error: undefined, description: undefined }] })],
				"is observed, by no words",
			],
			[[entry({ refusals: [{ ...typ, error: undefined }] })], "not both"],
			[[entry({ refusals: [{ ...typ, status: 200 }] })], "status is no refusal's"],
			[[entry({ refusals: [{ ...typ, refuser: "browser" }] })], "refuser is none known"],
			[[entry({ refusals: [{ ...typ, reading: "maybe" }] })], "reading is none known"],
			[[{ ...entry(), warning: [] }], "fields none has: warning"],
			[[entry({ reading: "constructor" })], "reading is none known"],
			[[entry({ failures: [{ ...failure, keys: ["jar-required"] }] })], "which no refusal shows"],
			[
				[entry({ result: "PASSED", reading: "passed", failures: undefined })],
				"is passed, yet a refusal shows",
			],
			[
				[
					entry({
						result: "PASSED",
						reading: "own-condition",
						refusals: [own, typ],
						failures: undefined,
					}),
				],
				"is own-condition, yet a refusal shows",
			],
			[
				[
					entry({
						result: "PASSED",
						reading: "before-wall",
						failures: undefined,
						warnings: [failure],
					}),
				],
				"passed, yet names warnings",
			],
			[[entry({ refusals: [{ ...typ, key: "x" }] })], "fields none has: key"],
		];
		for (const [value, said] of cases)
			expect(expectedProblems(value, keys).join("\n"), said).toContain(said);
	});

	it("takes the package's run A, one entry for each module of its plan under its one variant", () => {
		const a = expectedFor(
			"a",
			ledger().map((row) => row.key),
		);
		expect(a).toHaveLength(67);
		expect(new Set(a.map((entry) => JSON.stringify(entry.variant))).size).toBe(1);
		// A refusal's words read by the word table as the entry says: one row where observed, the rows it
		// might be (none for words of many causes) where unconfirmed; never a row's words where the test's own.
		for (const entry of a)
			for (const refusal of entry.refusals) {
				if (refusal.error === undefined || refusal.description === undefined) continue;
				const seen = {
					...refusal,
					error: refusal.error,
					description: refusal.description,
					dpopHeader: false,
					startedBefore: false,
				};
				const read = readingOf(seen);
				const at = `${entry.test}: ${refusal.description}`;
				if (refusal.reading === "observed")
					expect(read, at).toEqual({ kind: "observed", key: refusal.keys?.[0] });
				else if (refusal.reading === "own") expect(read, at).toEqual({ kind: "none" });
				else expect(read, at).toEqual({ kind: "unconfirmed", keys: refusal.keys ?? [] });
			}
	});
});
