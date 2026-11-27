import { describe, expect, it } from "vitest";
import { writtenJson } from "../written.ts";

describe("a JSON answer as a server writes it", () => {
	it("gives the text JSON writes where it holds no null", () => {
		const json = { a: "x", list: [1, { b: true }], n: 0 };
		expect(writtenJson(json)).toEqual({ text: JSON.stringify(json) });
	});

	it("gives the paths of the nulls inside it, an object's member or an array's element, at any depth, never the text", () => {
		const read = writtenJson({
			kept: "secret-value",
			top: null,
			address: { locality: "x", region: null },
			list: [{ item: null }, null],
			deep: { list: ["x", [null]] },
		});
		expect(read).toEqual({
			nulls: ["top", "address.region", "list[0].item", "list[1]", "deep.list[1][0]"],
		});
		expect(JSON.stringify(read)).not.toContain("secret-value");
		expect(writtenJson(["x", null])).toEqual({ nulls: ["[1]"] });
		// A member's name is written into its path as it is.
		expect(writtenJson({ "a.b": { "c[0]": null } })).toEqual({ nulls: ["a.b.c[0]"] });
		// A member named "" is a member too, at the top or nested.
		expect(writtenJson({ "": null })).toEqual({ nulls: [""] });
		expect(writtenJson({ "": { "": null }, a: [{ "": null }] })).toEqual({
			nulls: [".", "a[0]."],
		});
	});

	it("reads what JSON writes, so a value it writes as null is one: a number that is none, undefined in a list, a toJSON giving null, called once", () => {
		let calls = 0;
		const once = {
			toJSON: () => {
				calls += 1;
				return null;
			},
		};
		expect(
			writtenJson({
				nan: Number.NaN,
				infinite: Number.POSITIVE_INFINITY,
				list: [undefined],
				once,
				missing: undefined,
			}),
		).toEqual({ nulls: ["nan", "infinite", "list[0]", "once"] });
		expect(calls).toBe(1);
	});

	it("leaves, as written, a top-level null (no null inside it) and a value JSON writes as nothing", () => {
		expect(writtenJson(null)).toEqual({ text: "null" });
		expect(writtenJson(() => 1)).toStrictEqual({ text: undefined });
		expect(writtenJson({ toJSON: () => undefined })).toStrictEqual({ text: undefined });
	});

	it("walks an answer nested however deep JSON reads it, finding a null at its bottom", () => {
		const deep = (leaf: unknown) => {
			let value: unknown = leaf;
			for (let i = 0; i < 20_000; i++) value = { a: value };
			return value;
		};
		const clean = writtenJson(deep("x"));
		expect("text" in clean && clean.text?.length).toBe(20_000 * 6 + 3);
		expect(writtenJson(deep(null))).toEqual({ nulls: [Array(20_000).fill("a").join(".")] });
	});

	it("throws, as JSON throws, for a value JSON cannot write", () => {
		const cycle: Record<string, unknown> = {};
		cycle.self = cycle;
		expect(() => writtenJson(cycle)).toThrow(TypeError);
		expect(() => writtenJson({ n: 1n })).toThrow(TypeError);
		const thrown = new Error("no JSON");
		expect(() =>
			writtenJson({
				toJSON: () => {
					throw thrown;
				},
			}),
		).toThrow(thrown);
	});
});
