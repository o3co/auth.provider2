import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ledger, ledgerOf, ledgerProblems, pageOf, pagePath } from "../deviations.ts";

const row = {
	key: "a-choice",
	kind: "strict",
	standard: "RFC 0000",
	text: "an AS may",
	behaviour: "refused",
	why: "the threat model",
	decision: "L1",
};

describe("the deviations ledger", () => {
	it("is the page the repository holds, as written from the ledger", () => {
		expect(readFileSync(pagePath, "utf8")).toBe(pageOf(ledger()));
	});

	it("holds rows, the repository's ledger taken whole", () => {
		expect(ledger().length).toBeGreaterThan(0);
	});

	it("refuses a key named twice, a field empty or missing, an unknown kind or field, and a key of another form", () => {
		expect(ledgerProblems([row])).toEqual([]);
		expect(ledgerProblems([row, row])).toEqual(["the key a-choice is named twice"]);
		expect(ledgerProblems([{ ...row, why: " " }])).toEqual(["row 1 has no why"]);
		const { decision: _decision, ...without } = row;
		expect(ledgerProblems([without])).toEqual(["row 1 has no decision"]);
		expect(ledgerProblems([{ ...row, kind: "lenient" }])).toEqual([
			"row 1's kind is neither deviation nor strict",
		]);
		expect(ledgerProblems([{ ...row, note: "x" }])).toEqual(["row 1 has fields no row has: note"]);
		expect(ledgerProblems([{ ...row, key: "A_Choice" }])).toEqual([
			"row 1's key is not lowercase words joined by -",
		]);
		expect(ledgerProblems({})).toEqual(["the ledger is a list of rows"]);
		expect(() => ledgerOf(JSON.stringify([row, row]))).toThrow(/named twice/);
	});

	it("writes a row on one line of the table, a | in its text escaped", () => {
		const page = pageOf([{ ...row, kind: "strict", why: "one | two\nthree" }]);
		expect(page.split("\n").filter((l) => l.startsWith("| `a-choice`"))).toEqual([
			"| `a-choice` | strict | RFC 0000 | an AS may | refused | one \\| two three | L1 |",
		]);
	});
});
