import { describe, expect, it } from "vitest";
import { ledger } from "../../deviations/deviations.ts";
import { readingOf, type Seen, type Word, words, wordsProblems } from "../words.ts";

const seen = (over: Partial<Seen> = {}): Seen => ({
	refuser: "core",
	place: "par",
	error: "invalid_request_object",
	description: "not of the typ asked",
	dpopHeader: false,
	startedBefore: false,
	...over,
});

/** A word of a made-up row, the same words unless told otherwise. */
const twin = (key: string, over: Partial<Word> = {}): Word => ({
	key,
	refuser: "core",
	place: "par",
	error: "invalid_request",
	description: "the same",
	...over,
});
const keys = ["a-row", "b-row"];
const twinSeen = seen({ error: "invalid_request", description: "the same" });

describe("the provider's words for the ledger's rows", () => {
	it("names rows of the ledger alone, none with empty words, none two rows share unsaid", () => {
		expect(
			wordsProblems(
				words,
				ledger().map((row) => row.key),
			),
		).toEqual([]);
	});

	it("tells the row a refusal answers for, by every part of it", () => {
		expect(readingOf(seen())).toEqual({ kind: "observed", key: "jar-typ-required" });
		for (const other of [
			{ refuser: "front" },
			{ place: "start" },
			{ error: "invalid_request" },
			{ description: "not a JWT" },
		] as const)
			expect(readingOf(seen(other)), JSON.stringify(other)).toEqual({ kind: "none" });
	});

	it("tells two rows that share words apart by whether the request carried a DPoP header", () => {
		const named = seen({ description: "the request names no dpop_jkt" });
		expect(readingOf(named)).toEqual({ kind: "observed", key: "jar-dpop-jkt-required" });
		expect(readingOf({ ...named, dpopHeader: true })).toEqual({
			kind: "observed",
			key: "par-dpop-header-only",
		});
	});

	it("takes a used request's refusal for its row only where its request_uri was started before", () => {
		const used = seen({
			place: "start",
			error: "invalid_request",
			description: "the request was used already",
		});
		expect(readingOf({ ...used, startedBefore: true })).toEqual({
			kind: "observed",
			key: "request-uri-once",
		});
		// Another JAR under the same jti, answered in the same words: no row's.
		expect(readingOf(used)).toEqual({ kind: "none" });
	});

	it("leaves unconfirmed a refusal in words other causes share", () => {
		expect(
			readingOf(
				seen({ place: "token", error: "invalid_grant", description: "invalid refresh token" }),
			),
		).toEqual({ kind: "unconfirmed", keys: ["refresh-dpop-bound"] });
		expect(readingOf(seen({ place: "start", description: "item:claims" }))).toEqual({
			kind: "unconfirmed",
			keys: ["claims-null-nested"],
		});
	});

	it("leaves unconfirmed the words two rows answer alike, whether or not they say they are shared", () => {
		for (const table of [
			[twin("a-row"), twin("b-row")],
			[twin("a-row", { shared: true }), twin("b-row", { shared: true })],
		])
			expect(readingOf(twinSeen, table)).toEqual({ kind: "unconfirmed", keys });
	});

	it("refuses a table with two rows' words a request cannot tell apart, unless both say they are shared", () => {
		const said = "a-row and b-row: the same words, and not both say they are shared";
		expect(wordsProblems([twin("a-row"), twin("b-row")], keys)).toEqual([said]);
		expect(wordsProblems([twin("a-row", { shared: true }), twin("b-row")], keys)).toEqual([said]);
		expect(
			wordsProblems([twin("a-row", { shared: true }), twin("b-row", { shared: true })], keys),
		).toEqual([]);
		// A feature only one row names leaves the other row's words over both.
		expect(wordsProblems([twin("a-row", { dpopHeader: true }), twin("b-row")], keys)).toEqual([
			said,
		]);
		expect(wordsProblems([twin("a-row", { startedBefore: true }), twin("b-row")], keys)).toEqual([
			said,
		]);
		// Either order, and the same value named by both.
		for (const feature of ["dpopHeader", "startedBefore"] as const) {
			expect(
				wordsProblems([twin("a-row"), twin("b-row", { [feature]: true })], keys),
				feature,
			).toEqual([said]);
			expect(
				wordsProblems(
					[twin("a-row", { [feature]: true }), twin("b-row", { [feature]: true })],
					keys,
				),
				feature,
			).toEqual([said]);
		}
	});

	it("takes words that differ in any one part, or one row's words twice", () => {
		for (const over of [
			{ refuser: "front" },
			{ place: "start" },
			{ error: "invalid_request_object" },
			{ description: "another" },
		] as const)
			expect(
				wordsProblems([twin("a-row"), twin("b-row", over)], keys),
				JSON.stringify(over),
			).toEqual([]);
		for (const feature of ["dpopHeader", "startedBefore"] as const)
			expect(
				wordsProblems(
					[twin("a-row", { [feature]: true }), twin("b-row", { [feature]: false })],
					keys,
				),
				feature,
			).toEqual([]);
		expect(wordsProblems([twin("a-row"), twin("a-row")], keys)).toEqual([]);
	});

	it("refuses a word for no row of the ledger, and empty words", () => {
		const first = words[0] as Word;
		expect(
			wordsProblems(
				[
					{ ...first, key: "no-such-row" },
					{ ...first, description: "" },
					{ ...first, error: "" },
				],
				["jar-typ-required"],
			),
		).toEqual([
			"no-such-row: no row of the ledger",
			"jar-typ-required: its words are empty",
			"jar-typ-required: its words are empty",
		]);
	});
});
