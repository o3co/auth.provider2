import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonical, readJson } from "../text.ts";

/** A JSON text nested `depth` deep, in objects or arrays, around one leaf. */
const nested = (depth: number, inArrays: boolean, leaf: string) =>
	`${(inArrays ? "[" : '{"a":').repeat(depth)}${leaf}${(inArrays ? "]" : "}").repeat(depth)}`;

/** The rule as it was written, by recursion: the oracle the iterative walk keeps to, byte for byte. */
function recursive(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(recursive).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${recursive(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

describe("a JSON text nested however deep JSON reads it", () => {
	// Deeper than any stack the recursion had: a token's claims carry T's, as deep as a JAR's.
	const depth = 20_000;

	it("is read, a number past a double still refused at its bottom, never a RangeError", () => {
		for (const inArrays of [false, true]) {
			const read = readJson(nested(depth, inArrays, "1"));
			expect("value" in read).toBe(true);
			expect(readJson(nested(depth, inArrays, "1e400"))).toEqual({ error: "number" });
		}
	});

	it("is written canonically, never a RangeError", () => {
		for (const inArrays of [false, true]) {
			const text = nested(depth, inArrays, "1");
			expect(canonical(JSON.parse(text))).toBe(text);
		}
	});

	it("walks a list however long, finding a number past a double at its end", () => {
		const long = Array.from({ length: 300_000 }, () => 1);
		expect(readJson(`[${long.join(",")},1e400]`)).toEqual({ error: "number" });
		expect(canonical(long)).toBe(JSON.stringify(long));
	});
});

/** readJson's number check as it was written, by recursion: the oracle the iterative walk keeps to. */
const recursiveFinite = (x: unknown): boolean =>
	typeof x === "number"
		? Number.isFinite(x)
		: x !== null && typeof x === "object"
			? Object.values(x).every(recursiveFinite)
			: true;

describe("the number check, kept as it was", () => {
	it("refuses exactly the texts the recursive check refused for a number past a double", () => {
		const number = fc.oneof(
			fc.integer().map(String),
			fc.constantFrom("1e400", "-1e400", "1e308", "0.5"),
		);
		const json = fc.letrec<{ any: string; array: string; object: string }>((tie) => ({
			any: fc.oneof(
				{ depthSize: "small" },
				number,
				fc.constant('"x"'),
				fc.constant("null"),
				tie("array"),
				tie("object"),
			),
			array: fc.array(tie("any"), { maxLength: 5 }).map((items) => `[${items.join(",")}]`),
			object: fc
				.uniqueArray(fc.tuple(fc.string(), tie("any")), { maxLength: 5, selector: ([k]) => k })
				.map((members) => `{${members.map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(",")}}`),
		})).any;
		fc.assert(
			fc.property(json, (text) => {
				const read = readJson(text);
				expect("error" in read && read.error === "number").toBe(!recursiveFinite(JSON.parse(text)));
			}),
			{ numRuns: 2000, seed: 20261127 },
		);
	});
});

describe("the canonical text, kept byte for byte", () => {
	it("is what the recursive rule wrote for every value it wrote, JSON or not", () => {
		const leaf = fc.oneof(
			fc.jsonValue(),
			fc.constant(undefined),
			fc.constant(() => 1),
			fc.constant(Number.NaN),
			fc.constant(Number.POSITIVE_INFINITY),
		);
		const value = fc.letrec((tie) => ({
			any: fc.oneof({ depthSize: "small" }, leaf, tie("array"), tie("object")),
			array: fc.array(tie("any"), { maxLength: 5 }),
			object: fc.dictionary(
				fc.oneof(fc.string(), fc.constantFrom("__proto__", "", "a.b")),
				tie("any"),
				{
					maxKeys: 5,
				},
			),
		})).any;
		fc.assert(
			fc.property(value, (v) => {
				expect(canonical(v)).toBe(recursive(v));
			}),
			{ numRuns: 2000, seed: 20261127 },
		);
		const sparse: unknown[] = new Array(2);
		sparse[1] = 1;
		for (const v of [[undefined], [1, undefined, 2], { a: () => 1 }, sparse, undefined])
			expect(canonical(v)).toBe(recursive(v));
	});
});
