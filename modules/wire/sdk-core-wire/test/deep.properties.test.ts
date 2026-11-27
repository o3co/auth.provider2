import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonicalText, itemsFromJar } from "../src/contract.ts";

const jar = {
	iss: "rp-1",
	aud: "https://id.example",
	iat: 1,
	exp: 61,
	jti: "j-1",
	client_id: "rp-1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "s",
	scope: "openid",
	nonce: "n",
	code_challenge: "c",
	code_challenge_method: "S256",
	dpop_jkt: "k",
};
/**
 * A JSON text nested `depth` deep, in objects or arrays, around one leaf: its one member named `a`,
 * no space, so the text is its own canonical text, which no engine's recursive JSON.stringify need write.
 */
const nestedText = (depth: number, inArrays: boolean, leaf: string) =>
	`${(inArrays ? "[" : '{"a":').repeat(depth)}${leaf}${(inArrays ? "]" : "}").repeat(depth)}`;
const nested = (depth: number, inArrays: boolean, leaf: string) =>
	JSON.parse(nestedText(depth, inArrays, leaf));

/** The rule as it was written, by recursion: the oracle the iterative walk keeps to, byte for byte. */
function recursiveText(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(recursiveText).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${recursiveText(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

describe("a value nested however deep JSON reads it", () => {
	// Deeper than any stack the recursion had: an 8192-character JAR carries some thousands of levels.
	const depth = 20_000;

	it("gives its canonical text, never a RangeError", () => {
		for (const inArrays of [false, true]) {
			expect(canonicalText(nested(depth, inArrays, "1"))).toBe(nestedText(depth, inArrays, "1"));
		}
	});

	it("is read into T's items or refused for a null at its bottom, as a JAR's claims, never a RangeError", () => {
		for (const inArrays of [false, true]) {
			const asked = (leaf: string) => ({
				id_token: { x: { values: [nested(depth, inArrays, leaf)] } },
			});
			const read = itemsFromJar({ ...jar, claims: asked("1") }, "h");
			expect("items" in read && canonicalText(read.items.claims)).toBe(canonicalText(asked("1")));
			expect(itemsFromJar({ ...jar, claims: asked("null") }, "h")).toEqual({
				error: "item:claims",
			});
		}
	});
});

it("walks a list however long, as JSON reads it, finding a null at its end", () => {
	const long = Array.from({ length: 300_000 }, () => 1);
	const asked = { id_token: { x: { values: [...long, null] } } };
	expect(itemsFromJar({ ...jar, claims: asked }, "h")).toEqual({ error: "item:claims" });
	expect(canonicalText(long)).toBe(JSON.stringify(long));
});

/** T's claims check as it was written, by recursion: the oracle the iterative walk keeps to. */
const recursiveHoldsNull = (value: unknown): boolean =>
	value === null ||
	(Array.isArray(value)
		? value.some(recursiveHoldsNull)
		: typeof value === "object" && Object.values(value as object).some(recursiveHoldsNull));

describe("T's claims check, kept as it was", () => {
	/** Whether a JAR asking these claims (under no member the null form rewrites) is refused for a null. */
	const refused = (claims: unknown) =>
		"error" in itemsFromJar({ ...jar, claims: { asked: claims } }, "h");

	it("refuses exactly the claims the recursive check refused, JSON or not", () => {
		const leaf = fc.oneof(
			fc.jsonValue(),
			fc.constant(undefined),
			fc.constant(() => 1),
		);
		const value = fc.letrec((tie) => ({
			any: fc.oneof({ depthSize: "small" }, leaf, tie("array"), tie("object")),
			array: fc.array(tie("any"), { maxLength: 5 }),
			object: fc.dictionary(fc.string(), tie("any"), { maxKeys: 5 }),
		})).any;
		fc.assert(
			fc.property(value, (v) => {
				expect(refused(v)).toBe(recursiveHoldsNull({ asked: v }));
			}),
			{ numRuns: 2000, seed: 20261127 },
		);
		// A list by its indices, as `some` visits them: a named member ignored, an inherited index read.
		const named = Object.assign([1], { extra: null });
		const inherited: unknown[] = new Array(1);
		Object.setPrototypeOf(inherited, Object.assign(Object.create(Array.prototype), { 0: null }));
		for (const v of [named, inherited, [null], new Array(2)])
			expect(refused(v), String(v)).toBe(recursiveHoldsNull({ asked: v }));
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
				expect(canonicalText(v)).toBe(recursiveText(v));
			}),
			{ numRuns: 2000, seed: 20261127 },
		);
		// Its quirks, kept: a list's undefined writes as nothing, an object's function as `undefined`.
		const sparse: unknown[] = new Array(2);
		sparse[1] = 1;
		for (const v of [[undefined], [1, undefined, 2], { a: () => 1 }, sparse, undefined])
			expect(canonicalText(v)).toBe(recursiveText(v));
	});
});
