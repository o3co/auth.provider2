import { types } from "node:util";

/** A JSON answer as a server writes it: its text, or the paths of the nulls inside it (never their values). */
export type WrittenJson =
	| { readonly text: string | undefined }
	| { readonly nulls: readonly string[] };

// A Boolean's and a BigInt's slot readers, taken at load: a later patch to them changes neither.
const booleanOf = Boolean.prototype.valueOf;
const bigIntOf = BigInt.prototype.valueOf;
const { isRawJSON } = JSON as unknown as { isRawJSON: (value: unknown) => boolean };

/** ECMA-262 LengthOfArrayLike: ToLength of the `length` read, by ToNumber (`+`, which refuses a BigInt). */
const lengthOf = (length: unknown): number => {
	const n = Math.trunc(+(length as number));
	return n > 0 ? Math.min(n, Number.MAX_SAFE_INTEGER) : 0;
};

/**
 * A member's or element's value as JSON writes it (ECMA-262 SerializeJSONProperty, no replacer):
 * its toJSON called with its key, a boxed primitive unboxed, a raw JSON its text, then its text, or
 * the object to write, or undefined for one JSON leaves out.
 */
function written(value: unknown, key: string): string | object | undefined {
	if (
		(typeof value === "object" && value !== null) ||
		typeof value === "function" ||
		typeof value === "bigint"
	) {
		const toJSON = (value as { toJSON?: unknown }).toJSON;
		if (typeof toJSON === "function") value = Reflect.apply(toJSON, value, [key]);
	}
	if (typeof value === "object" && value !== null) {
		// A box by its slot (no tag or proxy fakes one), unboxed as JSON unboxes it: a number by ToNumber
		// (`+`, which refuses a BigInt), a string by ToString, a boolean's and a BigInt's by the slot.
		if (types.isNumberObject(value)) value = +(value as unknown as number);
		else if (types.isStringObject(value)) value = String(value);
		else if (types.isBooleanObject(value)) value = Reflect.apply(booleanOf, value, []);
		else if (types.isBigIntObject(value)) value = Reflect.apply(bigIntOf, value, []);
		else if (isRawJSON(value)) return (value as { rawJSON: string }).rawJSON;
	}
	if (value === null) return "null";
	switch (typeof value) {
		case "boolean":
			return value ? "true" : "false";
		case "string":
			return JSON.stringify(value);
		case "number":
			return Number.isFinite(value) ? String(value) : "null";
		case "bigint":
			throw new TypeError("Do not know how to serialize a BigInt");
		case "object":
			return value;
		default:
			return undefined;
	}
}

/**
 * The deepest a value is written, a contract: 100,000 open objects or lists, far past any answer.
 * Deeper, the write throws a RangeError, the class the engine's own stack throws, and a server
 * answers it as any failure (500, the class logged). It stops a toJSON in server code that opens a new
 * object without end before it takes the process's memory; request data cannot open one (JSON.parse
 * gives no functions).
 */
const deepest = 100_000;

/** An object or array being written: what is left of it, and whether a member is written yet. */
type Open =
	| { readonly of: Record<string, unknown>; readonly keys: string[]; at: number; wrote: boolean }
	| { readonly of: unknown[]; readonly length: number; at: number };

/**
 * A value's JSON text, byte for byte as JSON.stringify writes it, each toJSON, getter and trap called
 * in its order. Walked by a stack of its own, not by recursion: the engine's JSON.stringify recurses,
 * and Node 24's overflows on a value nested as deep as JSON.parse reads.
 */
function textOf(value: unknown): string | undefined {
	const parts: string[] = [];
	const open: Open[] = [];
	const within = new Set<object>();
	// Writes one value: its text, or opens it, a cycle refused as JSON refuses it.
	const put = (got: string | object) => {
		if (typeof got === "string") {
			parts.push(got);
			return;
		}
		// IsArray first, as the spec asks it before it looks for a cycle.
		const list = Array.isArray(got);
		if (within.has(got)) throw new TypeError("Converting circular structure to JSON");
		if (open.length >= deepest) throw new RangeError(`JSON nested deeper than ${deepest}`);
		within.add(got);
		if (list) {
			open.push({ of: got, length: lengthOf(got.length), at: 0 });
			parts.push("[");
		} else {
			open.push({
				of: got as Record<string, unknown>,
				keys: Object.keys(got),
				at: 0,
				wrote: false,
			});
			parts.push("{");
		}
	};
	const top = written(value, "");
	if (top === undefined) return undefined;
	put(top);
	for (let next = open.at(-1); next; next = open.at(-1)) {
		if ("keys" in next) {
			let got: string | object | undefined;
			let key = "";
			// A member JSON leaves out is passed over.
			while (got === undefined && next.at < next.keys.length) {
				key = next.keys[next.at++] as string;
				got = written(next.of[key], key);
			}
			if (got === undefined) {
				parts.push("}");
				within.delete(next.of);
				open.pop();
			} else {
				parts.push(`${next.wrote ? "," : ""}${JSON.stringify(key)}:`);
				next.wrote = true;
				put(got);
			}
		} else if (next.at < next.length) {
			const i = next.at++;
			if (i > 0) parts.push(",");
			put(written(next.of[i], String(i)) ?? "null");
		} else {
			parts.push("]");
			within.delete(next.of);
			open.pop();
		}
	}
	return parts.join("");
}

/**
 * The paths of the nulls inside a value read back from JSON, at any depth: an object's member or an
 * array's element, in the order read. Walked by a stack of its own, not by recursion, so an answer
 * nested however deep JSON reads it is walked whole.
 */
function nullsIn(value: unknown): string[] {
	const found: string[] = [];
	// The value itself has no path (a top-level null is not inside it); a member named "" has one.
	const left: [unknown, string | undefined][] = [[value, undefined]];
	for (let next = left.pop(); next; next = left.pop()) {
		const [at, path] = next;
		if (at === null) {
			if (path !== undefined) found.push(path);
		} else if (Array.isArray(at)) {
			for (let i = at.length - 1; i >= 0; i--) left.push([at[i], `${path ?? ""}[${i}]`]);
		} else if (typeof at === "object") {
			const members = Object.entries(at);
			for (let i = members.length - 1; i >= 0; i--) {
				const [key, member] = members[i] as [string, unknown];
				left.push([member, path === undefined ? key : `${path}.${key}`]);
			}
		}
	}
	return found;
}

/**
 * A JSON answer's value as a server writes it (OpenID Connect Core §13.3: the provider writes no
 * member as null; one it has no value for is left out): the text, or the paths of the nulls inside it.
 * It reads back what JSON wrote, so NaN, Infinity, undefined in a list, a raw null and a toJSON giving
 * null are nulls, each toJSON called once. A top-level null holds none inside it, and a value JSON
 * writes as nothing has no text: both are left as written. A value JSON cannot write (a cycle, a
 * BigInt, a toJSON that throws) throws what JSON throws, its class the same; what a server answers
 * then is its own.
 */
export function writtenJson(json: unknown): WrittenJson {
	const text = textOf(json);
	if (text === undefined) return { text };
	const nulls = nullsIn(JSON.parse(text));
	return nulls.length > 0 ? { nulls } : { text };
}
