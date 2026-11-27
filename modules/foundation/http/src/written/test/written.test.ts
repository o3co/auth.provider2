import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { type WrittenJson, writtenJson } from "../written.ts";

// Raw JSON (ES2025's JSON.rawJSON), which the TypeScript lib here does not yet name.
const { rawJSON } = JSON as unknown as { rawJSON: (text: string) => object };

/** The rule as it was written, by the engine's JSON and a walk of the text read back: the oracle. */
function engineWritten(json: unknown): WrittenJson {
	const text: string | undefined = JSON.stringify(json);
	if (text === undefined) return { text };
	const nulls: string[] = [];
	const walk = (at: unknown, path: string | undefined): void => {
		if (at === null) {
			if (path !== undefined) nulls.push(path);
		} else if (Array.isArray(at)) {
			for (const [i, item] of at.entries()) walk(item, `${path ?? ""}[${i}]`);
		} else if (typeof at === "object")
			for (const [key, member] of Object.entries(at))
				walk(member, path === undefined ? key : `${path}.${key}`);
	};
	walk(JSON.parse(text), undefined);
	return nulls.length > 0 ? { nulls } : { text };
}

/** A value JSON writes in each of its ways, its toJSONs and getters noting each call they take. */
const anyValue = (calls: string[]) => {
	const leaf = fc.oneof(
		fc.jsonValue(),
		fc.constantFrom(
			undefined,
			Number.NaN,
			-0,
			Number.NEGATIVE_INFINITY,
			1e21,
			"\ud800",
			Symbol("s"),
		),
		fc.constant(() => 1),
		fc.constantFrom(new Number(2), new String("s"), new Boolean(false), Object(Symbol("b"))),
	);
	return fc.letrec((tie) => ({
		any: fc.oneof(
			{ depthSize: "small" },
			leaf,
			tie("array"),
			tie("object"),
			tie("toJSON"),
			tie("getter"),
		),
		array: fc.array(tie("any"), { maxLength: 4 }),
		object: fc.dictionary(
			fc.oneof(fc.string(), fc.constantFrom("__proto__", "", "a.b")),
			tie("any"),
			{
				maxKeys: 4,
			},
		),
		toJSON: tie("any").map((v) => ({
			toJSON: (key: string) => {
				calls.push(`toJSON ${JSON.stringify(key)}`);
				return v;
			},
		})),
		getter: fc.tuple(fc.string(), tie("any")).map(([name, v]) =>
			Object.defineProperty({}, name, {
				enumerable: true,
				get: () => {
					calls.push(`get ${JSON.stringify(name)}`);
					return v;
				},
			}),
		),
	})).any;
};

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

	it("walks an answer nested 20,000 deep, past the engine's stack, finding a null at its bottom", () => {
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

	it("writes what the engine's JSON writes and finds the nulls reading it back finds, calling the same toJSONs and getters in the same order", () => {
		const calls: string[] = [];
		fc.assert(
			fc.property(anyValue(calls), (value) => {
				calls.length = 0;
				const expected = engineWritten(value);
				const engineCalls = calls.splice(0);
				expect(writtenJson(value)).toEqual(expected);
				expect(calls).toEqual(engineCalls);
			}),
			{ numRuns: 2000, seed: 20261127 },
		);
		// A list read as JSON reads it: by its length and indices, holes and inherited ones too.
		const holes: unknown[] = new Array(3);
		holes[1] = null;
		const inherited: unknown[] = new Array(1);
		Object.setPrototypeOf(inherited, Object.assign(Object.create(Array.prototype), { 0: 7 }));
		const proxied = new Proxy([1, null], {});
		const named = Object.assign([1], { extra: null });
		const toJSONOnBigInt = { n: Object.assign(Object(1n), { toJSON: () => "1" }) };
		for (const v of [holes, inherited, proxied, named, toJSONOnBigInt])
			expect(writtenJson(v)).toEqual(engineWritten(v));
		expect(() => writtenJson([Object(2n)])).toThrow(TypeError);
	});

	it("does as the engine's JSON does where a value's own hooks could tell them apart, each built afresh for both", () => {
		/** Its outcome (an answer, or the class of what was thrown) and the hooks it called, by a writer. */
		const run = (make: (log: string[]) => unknown, write: (json: unknown) => WrittenJson) => {
			const log: string[] = [];
			const value = make(log);
			try {
				return { answer: write(value), log };
			} catch (error) {
				return { threw: (error as Error).constructor.name, log };
			}
		};
		/** A proxy noting each trap JSON could take on it. */
		const traced = <T extends object>(target: T, log: string[], name: string): T =>
			new Proxy(target, {
				get(t, k, r) {
					log.push(`${name} get ${String(k)}`);
					return Reflect.get(t, k, r);
				},
				ownKeys(t) {
					log.push(`${name} ownKeys`);
					return Reflect.ownKeys(t);
				},
				getOwnPropertyDescriptor(t, k) {
					log.push(`${name} describe ${String(k)}`);
					return Reflect.getOwnPropertyDescriptor(t, k);
				},
				apply(t, self, args) {
					log.push(`${name} apply`);
					return Reflect.apply(t as () => unknown, self, args);
				},
			});
		const noting =
			<T>(log: string[], name: string, give: T) =>
			() => {
				log.push(name);
				return give;
			};
		const shared = { s: 1 };
		const cases: Record<string, (log: string[]) => unknown> = {
			"a boxed number converted to a BigInt": () => [
				Object.assign(new Number(0), { [Symbol.toPrimitive]: () => 1n }),
			],
			"a boxed number whose valueOf gives a BigInt": () => ({
				n: Object.assign(new Number(1), { valueOf: () => 10n }),
			}),
			"a list's length read as a BigInt": () =>
				new Proxy([7], { get: (t, k, r) => (k === "length" ? 1n : Reflect.get(t, k, r)) }),
			"a list's length converted by its own valueOf": (log) =>
				new Proxy([7, 8, 9], {
					get: (t, k, r) =>
						k === "length" ? { valueOf: noting(log, "length", 2) } : Reflect.get(t, k, r),
				}),
			"a toJSON whose `call` is none": () => ({ toJSON: Object.assign(() => 7, { call: null }) }),
			"a toJSON that is a proxy": (log) => ({ a: { toJSON: traced(() => null, log, "toJSON") } }),
			"members whose order is the proxy's": (log) =>
				new Proxy(
					{ b: null, "2": null, "1": null },
					{
						ownKeys(t) {
							log.push("ownKeys");
							return ["b", "2", "1"].filter((k) => k in t);
						},
					},
				),
			"a proxied list and object, their traps in order": (log) => ({
				list: traced([1, null, { a: 2 }], log, "list"),
				object: traced({ z: [3], a: undefined }, log, "object"),
			}),
			"raw JSON": () => ({
				a: rawJSON("null"),
				b: [rawJSON("1e400"), rawJSON('"s"')],
			}),
			"raw JSON with no null": () => ({ b: [rawJSON("1e400")] }),
			"boxed primitives converting by their own hooks": (log) => [
				Object.assign(new Number(1), { valueOf: noting(log, "number", 5) }),
				Object.assign(new String("s"), { toString: noting(log, "string", "t") }),
				Object.assign(new Boolean(false), { valueOf: noting(log, "boolean", true) }),
				Object.assign(new Number(1), {
					[Symbol.toPrimitive]: noting(log, "primitive", Number.NaN),
				}),
			],
			"a callable with a toJSON": () => ({
				f: Object.assign(() => 1, { toJSON: () => "f" }),
				g: () => 1,
			}),
			"a getter taking a later member away": (log) => {
				const o: Record<string, unknown> = {};
				Object.defineProperty(o, "a", {
					enumerable: true,
					get: () => {
						log.push("a");
						delete o.b;
						return 1;
					},
				});
				o.b = 2;
				return { o, order: Object.keys(o) };
			},
			"a toJSON growing the list being written": () => {
				const list: unknown[] = [];
				list.push({ toJSON: () => list.push(2) }, 1);
				return list;
			},
			"one object twice, no cycle": () => [shared, { again: shared }],
			"a toJSON whose result makes a cycle": () => {
				const a: Record<string, unknown> = {};
				a.self = { toJSON: () => a };
				return a;
			},
			"a toJSON taking a cycle away": () => {
				const a: Record<string, unknown> = {};
				a.self = a;
				a.toJSON = () => "cut";
				return a;
			},
			"a toJSON whose result is written as it is, its own toJSON not called": () => ({
				a: {
					x: 1,
					toJSON() {
						return { ...this };
					},
				},
			}),
			"a toJSON opening a new object without end": () => ({
				a: {
					toJSON() {
						return [{ toJSON: this.toJSON }];
					},
				},
			}),
		};
		for (const [name, make] of Object.entries(cases))
			expect(run(make, writtenJson), name).toEqual(run(make, engineWritten));
		// A BigInt's toJSON is looked up on its prototype, a primitive's too.
		const bigIntJSON = Object.getOwnPropertyDescriptor(BigInt.prototype, "toJSON");
		Object.defineProperty(BigInt.prototype, "toJSON", {
			configurable: true,
			value(this: bigint, key: string) {
				return `${this}@${key}`;
			},
		});
		try {
			const make = () => ({ n: 1n, list: [2n, Object(3n)] });
			expect(run(make, writtenJson)).toEqual(run(make, engineWritten));
		} finally {
			if (bigIntJSON) Object.defineProperty(BigInt.prototype, "toJSON", bigIntJSON);
			else delete (BigInt.prototype as { toJSON?: unknown }).toJSON;
		}
	});

	it("writes 100,000 open objects or lists deep, and refuses one deeper by a RangeError, on every engine", () => {
		for (const inArrays of [false, true]) {
			const text = (depth: number) =>
				`${(inArrays ? "[" : '{"a":').repeat(depth)}0${(inArrays ? "]" : "}").repeat(depth)}`;
			const deep = (depth: number) => {
				let value: unknown = 0;
				for (let i = 0; i < depth; i++) value = inArrays ? [value] : { a: value };
				return value;
			};
			expect(writtenJson(deep(100_000))).toEqual({ text: text(100_000) });
			expect(() => writtenJson(deep(100_001))).toThrow(RangeError);
		}
	});
});
