/** A canonical JSON text: object keys sorted, undefined members left out, so both sides build the same bytes. */
export function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

export const unique = <T>(list: readonly T[], key: (item: T) => unknown) =>
	list.every((item, i) => list.findIndex((other) => key(other) === key(item)) === i);

/**
 * A JSON text as read, or why it is refused: not JSON, a key named twice in one object at any depth
 * (keys compared as decoded, escapes and all), or a number past a double.
 */
export function readJson(text: string): { readonly value: unknown } | { readonly error: string } {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return { error: "not_json" };
	}
	// The text is JSON: a string is a key where an object's `{` or `,` comes right before it.
	const open: (string[] | undefined)[] = [];
	let before = "";
	for (let i = 0; i < text.length; i++) {
		const c = text.charAt(i);
		if (c === '"') {
			let end = i + 1;
			while (text.charAt(end) !== '"') end += text.charAt(end) === "\\" ? 2 : 1;
			const keys = open[open.length - 1];
			if (keys && (before === "{" || before === ",")) {
				const key = JSON.parse(text.slice(i, end + 1)) as string;
				if (keys.includes(key)) return { error: `duplicate_key:${key}` };
				keys.push(key);
			}
			before = '"';
			i = end;
		} else if (c === "{" || c === "[") {
			open.push(c === "{" ? [] : undefined);
			before = c;
		} else if (c === "}" || c === "]") {
			open.pop();
			before = c;
		} else if (c.trim() !== "") before = c;
	}
	const finite = (x: unknown): boolean =>
		typeof x === "number"
			? Number.isFinite(x)
			: x !== null && typeof x === "object"
				? Object.values(x).every(finite)
				: true;
	return finite(value) ? { value } : { error: "number" };
}

export const isObject = (x: unknown): x is Record<string, unknown> =>
	x !== null && typeof x === "object" && !Array.isArray(x);

/** P-256's field prime and its curve's b (a = -3). */
const p256 = Object.freeze({
	p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
	b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
});
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** A 32-byte value from its 43 base64url characters, the last one's two spare bits zero; none for any other. */
export function coordinate(text: unknown): bigint | undefined {
	if (typeof text !== "string" || text.length !== 43) return undefined;
	let value = 0n;
	for (const char of text) {
		const at = alphabet.indexOf(char);
		if (at < 0) return undefined;
		value <<= 6n;
		for (let bit = 32, big = 32n; bit >= 1; bit >>= 1, big >>= 1n) if (at & bit) value |= big;
	}
	return (value & 3n) === 0n ? value >> 2n : undefined;
}
const modP = (n: bigint) => ((n % p256.p) + p256.p) % p256.p;
/** Whether the coordinates name a point of P-256: each below the prime, y² = x³ − 3x + b. */
export const onP256 = (x: bigint, y: bigint) =>
	x < p256.p && y < p256.p && modP(y * y) === modP(x * x * x - 3n * x + p256.b);

/** How many bytes a text takes in UTF-8, a lone surrogate as the three of U+FFFD. */
export function utf8Length(text: string): number {
	let bytes = 0;
	for (const char of text) {
		const point = char.codePointAt(0) ?? 0;
		bytes += point < 0x80 ? 1 : point < 0x800 ? 2 : point < 0x10000 ? 3 : 4;
	}
	return bytes;
}

/** Bytes from their one unpadded base64url spelling; none for any other. */
export function bytesOf(text: string): number[] | undefined {
	const rest = text.length % 4;
	if (rest === 1) return undefined;
	const bits: number[] = [];
	for (const char of text) {
		const at = alphabet.indexOf(char);
		if (at < 0) return undefined;
		for (let bit = 32; bit >= 1; bit >>= 1) bits.push(at & bit ? 1 : 0);
	}
	const spare = bits.length % 8;
	if (bits.slice(bits.length - spare).some((b) => b === 1)) return undefined;
	const bytes: number[] = [];
	for (let at = 0; at + 8 <= bits.length; at += 8)
		bytes.push(bits.slice(at, at + 8).reduce((n, b) => n * 2 + b, 0));
	return bytes;
}
/** Text from strict UTF-8 (shortest forms, no surrogates); none for any other bytes. */
export function textOf(bytes: readonly number[]): string | undefined {
	let text = "";
	for (let at = 0; at < bytes.length; ) {
		const first = bytes[at] ?? 0;
		const size =
			first < 0x80
				? 1
				: first >= 0xc2 && first < 0xe0
					? 2
					: first >= 0xe0 && first < 0xf0
						? 3
						: first >= 0xf0 && first < 0xf5
							? 4
							: 0;
		if (size === 0 || at + size > bytes.length) return undefined;
		let point = size === 1 ? first : first & (0xff >> (size + 1));
		for (let k = 1; k < size; k++) {
			const next = bytes[at + k] ?? 0;
			if ((next & 0xc0) !== 0x80) return undefined;
			point = point * 64 + (next & 0x3f);
		}
		const least = [0, 0, 0x80, 0x800, 0x10000][size] ?? 0;
		if (point < least || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return undefined;
		text += String.fromCodePoint(point);
		at += size;
	}
	return text;
}
