import {
	type FieldSpec,
	headerLength,
	maxReplyBody,
	maxRequestBody,
	outcomes,
	type RequestKind,
	replies,
	requests,
	type WireErrorName,
	wireErrors,
} from "@mod/front-core-wire";
import { describe, expect, it } from "vitest";
import {
	decodeReply,
	decodeRequest,
	encodeReply,
	encodeRequest,
	frameSplitter,
	type Message,
	WireEncodeError,
} from "../src/contract.ts";
import { fuzzer } from "../src/testing.ts";

const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261123);
const cases = Number(process.env.WIRE_FUZZ_CASES ?? 4000);
const { int, pick, randomBytes, validFrame, mutate } = fuzzer(seed);
const kinds = Object.keys(requests) as RequestKind[];

// A reference decoder written apart from the codec (arrays and regular expressions), sharing only the schema.
const pattern = {
	b64url: /^[A-Za-z0-9_-]+$/,
	jws: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
};
function referenceSyntax(spec: FieldSpec, value: number[]): boolean {
	const latin1 = () => Buffer.from(value).toString("latin1");
	switch (spec.type) {
		case "bytes":
			return true;
		case "enum":
			return (value[0] ?? 0) < (spec.values ?? 0);
		case "visible":
			return value.every((c) => c >= 0x21 && c <= 0x7e);
		case "b64url":
		case "jws":
			return pattern[spec.type].test(latin1());
		case "utf8": {
			const text = Buffer.from(value).toString("utf8");
			const plain = [...text].every((ch) => (ch.codePointAt(0) ?? 0) >= 0x20 && ch !== "\u007f");
			return Buffer.from(text, "utf8").equals(Buffer.from(value)) && plain;
		}
	}
}
/** The frames a side reads: each tag's fields, and the body's limit. */
type Table = { readonly fields: ReadonlyMap<number, readonly FieldSpec[]>; readonly max: number };
const requestTable: Table = {
	fields: new Map(Object.values(requests).map((r) => [r.code, r.fields as readonly FieldSpec[]])),
	max: maxRequestBody,
};
const replyTable: Table = {
	fields: new Map(
		(Object.keys(outcomes) as (keyof typeof outcomes)[]).map((o) => [
			outcomes[o],
			replies[o] as readonly FieldSpec[],
		]),
	),
	max: maxReplyBody,
};
type Verdict =
	| { readonly ok: true }
	| { readonly ok: false; readonly code: WireErrorName; readonly id: number };
/** The reference's reading: accepted, or the code and the id the header gave (0 before an id is read). */
function referenceRead(bytes: Uint8Array, table: Table): Verdict {
	const a = Array.from(bytes);
	const no = (code: WireErrorName, id: number): Verdict => ({ ok: false, code, id });
	if (a.length < headerLength) return no("truncated", 0);
	if (a[0] !== 1) return no("version", 0);
	const id =
		((a[2] ?? 0) * 2 ** 24 + (a[3] ?? 0) * 2 ** 16 + (a[4] ?? 0) * 2 ** 8 + (a[5] ?? 0)) >>> 0;
	const length = (a[6] ?? 0) * 2 ** 24 + (a[7] ?? 0) * 2 ** 16 + (a[8] ?? 0) * 2 ** 8 + (a[9] ?? 0);
	if (length > table.max) return no("length", id);
	const fields = table.fields.get(a[1] ?? -1);
	if (!fields) return no("kind", id);
	if (a.length !== headerLength + length)
		return no(a.length < headerLength + length ? "truncated" : "trailing", id);
	let at = headerLength;
	for (const f of fields) {
		if (at + 2 > a.length) return no("truncated", id);
		const n = (a[at] ?? 0) * 256 + (a[at + 1] ?? 0);
		at += 2;
		if (at + n > a.length) return no("truncated", id);
		if (n < f.min || n > f.max) return no("fieldLength", id);
		if (n > 0 && !referenceSyntax(f, a.slice(at, at + n)))
			return no(f.type === "enum" ? "enumRange" : "fieldSyntax", id);
		at += n;
	}
	return at === a.length ? { ok: true } : no("trailing", id);
}
/** A value within a field's spec, from the fuzzer's draws: what an honest side sends. */
function within(spec: FieldSpec, n: number): unknown {
	switch (spec.type) {
		case "bytes":
			return randomBytes(n);
		case "enum":
			return int(spec.values ?? 1);
		case "b64url":
			return "A".repeat(n);
		case "visible":
			return "7".repeat(n);
		case "utf8":
			return Array.from({ length: Math.max(1, Math.floor(n / 4)) }, () =>
				pick(["a", "é", "名", "😀"]),
			).join("");
		case "jws":
			return n < 5 ? "" : `${"a".repeat(n - 4)}.b.c`;
	}
}
/** A reply of an outcome its encoder takes, each field drawn within its spec. */
function validReply(outcome: keyof typeof outcomes): Uint8Array {
	let last: unknown;
	for (let tries = 0; tries < 100; tries++) {
		const message = Object.fromEntries(
			(replies[outcome] as readonly FieldSpec[]).map((f) => [
				f.name,
				within(f, f.min + int(Math.min(f.max, 300) - f.min + 1)),
			]),
		);
		try {
			return encodeReply({ outcome, id: int(2 ** 32), message } as never);
		} catch (error) {
			// A draw at a length's edge; draw again, a hundred times at most.
			last = error;
		}
	}
	throw new Error(`no ${outcome} reply drawn: ${String(last)}`);
}

/** A frame written apart from the codec: its header, then each field's length and bytes. */
function frameOf(tag: number, id: number, fields: readonly Uint8Array[]): Uint8Array {
	const body = fields.flatMap((f) => [f.length >> 8, f.length & 0xff, ...f]);
	const n = body.length;
	return Uint8Array.from([
		1,
		tag,
		id >>> 24,
		(id >>> 16) & 0xff,
		(id >>> 8) & 0xff,
		id & 0xff,
		n >>> 24,
		(n >>> 16) & 0xff,
		(n >>> 8) & 0xff,
		n & 0xff,
		...body,
	]);
}
/** A field's value of exactly `n` bytes, within its spec, and the bytes it is written as. */
function exact(
	spec: FieldSpec,
	n: number,
): { readonly value: unknown; readonly bytes: Uint8Array } {
	const text = (t: string) => ({ value: t, bytes: Buffer.from(t, "utf8") });
	switch (spec.type) {
		case "bytes": {
			const b = randomBytes(n);
			return { value: b, bytes: b };
		}
		case "enum": {
			const v = int(spec.values ?? 1);
			return { value: v, bytes: Uint8Array.of(v) };
		}
		case "b64url":
			return text("A".repeat(n));
		case "visible":
			return text("~".repeat(n));
		case "utf8":
			return text("é".repeat(Math.floor(n / 2)) + "a".repeat(n % 2));
		case "jws":
			return text(n === 0 ? "" : `${"a".repeat(n - 4)}.b.c`);
	}
}

/** A frame with one enum field's byte set past, or at, its count: walked to by its fields' lengths. */
function aimedEnum(bytes: Uint8Array, table: Table): Uint8Array {
	const fields = table.fields.get(bytes[1] ?? -1) ?? [];
	const out = new Uint8Array(bytes);
	const enums: [number, FieldSpec][] = [];
	let at = headerLength;
	for (const f of fields) {
		const n = (out[at] ?? 0) * 256 + (out[at + 1] ?? 0);
		if (f.type === "enum" && n === 1) enums.push([at + 2, f]);
		at += 2 + n;
	}
	if (enums.length === 0) return out;
	const [offset, f] = pick(enums);
	out[offset] = pick([f.values ?? 1, (f.values ?? 1) + 1, 0xff].filter((v) => v <= 0xff));
	return out;
}
/** Frames of a side whose one field is a text no well-formed sender writes: a JWS of an empty segment, a BOM first. */
function edgeFrames(table: Table): Uint8Array[] {
	const frames: Uint8Array[] = [];
	for (const [tag, fields] of table.fields) {
		for (const [i, f] of fields.entries()) {
			const texts =
				f.type === "jws"
					? ["a..c", ".a.b", "a.b.", "a.b.c.", "..", "a.b"]
					: f.type === "utf8"
						? ["\ufeffa", "a\ufeff"]
						: [];
			// Each character class's edge: the byte at it and the byte past it, for each text field.
			if (f.type === "visible" || f.type === "b64url" || f.type === "jws" || f.type === "utf8") {
				for (const b of [
					0x1f, 0x20, 0x21, 0x2b, 0x2c, 0x2d, 0x2f, 0x30, 0x39, 0x3a, 0x40, 0x41, 0x5a, 0x5b, 0x5e,
					0x5f, 0x60, 0x61, 0x7a, 0x7b, 0x7e, 0x7f,
				]) {
					// Padded with letters to the field's least, so a field of a fixed length is probed too.
					const pad = (n: number) => Array.from({ length: Math.max(0, n) }, () => 0x61);
					const field =
						f.type === "jws"
							? Uint8Array.from([...pad(f.min - 5), 0x61, b, 0x2e, 0x62, 0x2e, 0x63])
							: Uint8Array.from([...pad(f.min - 1), b]);
					if (field.length < f.min || field.length > f.max) continue;
					const drawn = fields.map((g, j) =>
						j === i
							? field
							: exact(g, g.type === "jws" && g.min > 0 ? Math.max(g.min, 5) : g.min).bytes,
					);
					frames.push(frameOf(tag, 13, drawn));
				}
			}
			for (const t of texts) {
				const drawn = fields.map((g, j) =>
					j === i
						? Buffer.from(t, "utf8")
						: exact(g, g.type === "jws" && g.min > 0 ? Math.max(g.min, 5) : g.min).bytes,
				);
				frames.push(frameOf(tag, 11, drawn));
			}
		}
	}
	return frames;
}

describe("a round trip", () => {
	it("reads every well-formed frame back as it was written", () => {
		for (const kind of kinds) {
			for (let i = 0; i < 50; i++) {
				const frame = validFrame(kind);
				const read = decodeRequest(frame);
				expect(read.ok, `${kind} ${read.ok ? "" : read.error}`).toBe(true);
				if (read.ok) {
					expect(read.value.kind).toBe(kind);
					const again = encodeRequest(
						kind,
						read.value.id,
						read.value.message as Message<typeof kind>,
					);
					expect(Buffer.from(again).equals(Buffer.from(frame))).toBe(true);
				}
			}
		}
	});

	it("reads each reply's outcome back", () => {
		for (const reply of [
			{ outcome: "ok", id: 7, message: { body: randomBytes(40), dpopNonce: "nonce" } },
			{
				outcome: "refused",
				id: 8,
				message: { error: 3, detail: "bad grant", dpopNonce: "", retryAfter: "30" },
			},
			{ outcome: "rejected", id: 9, message: { code: wireErrors.kind } },
		] as const) {
			const read = decodeReply(encodeReply(reply));
			expect(read.ok && read.value.outcome).toBe(reply.outcome);
			expect(read.ok && read.value.id).toBe(reply.id);
		}
	});

	it("refuses to encode a field outside its spec, naming the field", () => {
		const message = {
			source: "",
			clientId: "",
			request: "a.b.c",
			requestUri: "",
			eEnc: randomBytes(65),
			eSigX: randomBytes(32),
			eSigY: randomBytes(32),
		};
		expect(() => encodeRequest("loginStart", 1, message)).toThrow(WireEncodeError);
		expect(() => encodeRequest("loginStart", 1, message)).toThrow("wire: clientId fieldLength");
	});

	it("refuses an enum's number past its count, never wrapping it to a byte within, and a text with a lone surrogate", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok || decoded.value.kind !== "continue") throw new Error("a valid frame");
		const { message } = decoded.value;
		expect(() => encodeRequest("continue", 1, { ...message, seq: 16 })).not.toThrow();
		for (const seq of [17, 255, 256, 272, -1, 1.5])
			expect(() => encodeRequest("continue", 1, { ...message, seq }), String(seq)).toThrow(
				"wire: seq enumRange",
			);
		expect(() => encodeRequest("continue", 1, { ...message, body: "a\ud800" })).toThrow(
			"wire: body fieldSyntax",
		);
	});

	it("refuses a field given as another type than its own, never sending it as an empty one", () => {
		const decoded = decodeRequest(validFrame("continue"));
		if (!decoded.ok || decoded.value.kind !== "continue") throw new Error("a valid frame");
		const { message } = decoded.value;
		for (const [name, value] of [
			["body", 5],
			["body", ["x"]],
			["statement", { toString: () => "a.b.c" }],
			["sig", "AAAA"],
			["enc", [1, 2]],
		] as const)
			expect(
				() => encodeRequest("continue", 1, { ...message, [name]: value } as never),
				name,
			).toThrow(`wire: ${name} fieldSyntax`);
		// Absent, a field of no least length is empty, as before.
		const { sig: _, ...absent } = message;
		expect(() => encodeRequest("continue", 1, absent as never)).not.toThrow();
	});

	it("refuses a reply's field outside its spec as given: its enum past its count, a text malformed or of another type", () => {
		const refused = { error: 254, detail: "", dpopNonce: "", retryAfter: "" };
		expect(() =>
			encodeReply({ outcome: "refused", id: 1, message: refused } as never),
		).not.toThrow();
		for (const [message, code] of [
			[{ ...refused, error: 255 }, "error enumRange"],
			[{ ...refused, error: 256 }, "error enumRange"],
			[{ ...refused, detail: "a\ud800" }, "detail fieldSyntax"],
			[{ ...refused, detail: 5 }, "detail fieldSyntax"],
		] as const)
			expect(() => encodeReply({ outcome: "refused", id: 1, message } as never)).toThrow(
				`wire: ${code}`,
			);
		expect(() =>
			encodeReply({ outcome: "rejected", id: 1, message: { code: 256 } } as never),
		).toThrow("wire: code enumRange");
		expect(() =>
			encodeReply({ outcome: "ok", id: 1, message: { body: "{}", dpopNonce: "" } } as never),
		).toThrow("wire: body fieldSyntax");
	});
});

describe("random frames and mutations of well-formed ones", () => {
	/** Reads each frame by the codec and the reference, counting where they part. */
	function fuzz(
		read: (b: Uint8Array) => ReturnType<typeof decodeRequest | typeof decodeReply>,
		table: Table,
		again: (v: never) => Uint8Array,
	) {
		const counted = { cases: 0, accepted: 0, disagreed: 0, nonCanonical: 0, threw: 0 };
		const codes = new Map<string, number>();
		/** The first case that parted from the reference, by its index and bytes, for the failure's message. */
		let first = "";
		const note = (bytes: Uint8Array) => {
			if (first === "")
				first = `seed ${seed}, case ${counted.cases}: ${Buffer.from(bytes).toString("hex").slice(0, 200)}`;
		};
		const check = (bytes: Uint8Array) => {
			counted.cases++;
			let got: ReturnType<typeof read>;
			try {
				got = read(bytes);
			} catch {
				counted.threw++;
				note(bytes);
				return;
			}
			const expected = referenceRead(bytes, table);
			const same = got.ok
				? expected.ok
				: !expected.ok && expected.code === got.error && expected.id === got.id;
			if (!same) {
				counted.disagreed++;
				note(bytes);
			}
			if (got.ok) {
				counted.accepted++;
				if (!Buffer.from(again(got.value as never)).equals(Buffer.from(bytes))) {
					counted.nonCanonical++;
					note(bytes);
				}
			} else codes.set(got.error, (codes.get(got.error) ?? 0) + 1);
		};
		return { counted, codes, check, first: () => first };
	}

	it(
		"never throws, agrees with the reference decoder on the verdict, its code and its id, takes only canonical frames, a request",
		() => {
			const { counted, codes, check, first } = fuzz(
				decodeRequest,
				requestTable,
				(v: { kind: RequestKind; id: number; message: never }) =>
					encodeRequest(v.kind, v.id, v.message),
			);
			for (let i = 0; i < cases; i++) check(randomBytes(int(200)));
			for (let i = 0; i < cases; i++) check(mutate(validFrame(pick(kinds))));
			// Aimed where a mutation rarely lands: an enum's byte at or past its count.
			for (let i = 0; i < cases / 4; i++) check(aimedEnum(validFrame(pick(kinds)), requestTable));
			const edges = edgeFrames(requestTable);
			for (const frame of edges) check(frame);
			expect(edges.length).toBeGreaterThan(0);
			expect(counted, first()).toMatchObject({ threw: 0, disagreed: 0, nonCanonical: 0 });
			expect(counted.accepted).toBeGreaterThan(0);
			// Every code the wire names is reached, each more than a few times.
			for (const code of Object.keys(wireErrors))
				expect(codes.get(code) ?? 0, code).toBeGreaterThan(3);
		},
		Math.max(5000, cases * 4),
	);

	it(
		"never throws, agrees with the reference decoder on the verdict, its code and its id, takes only canonical frames, a reply the Front reads",
		() => {
			const outcomeNames = Object.keys(outcomes) as (keyof typeof outcomes)[];
			const { counted, codes, check, first } = fuzz(
				decodeReply,
				replyTable,
				encodeReply as (v: never) => Uint8Array,
			);
			for (let i = 0; i < cases; i++) check(randomBytes(int(200)));
			for (let i = 0; i < cases; i++) check(mutate(validReply(pick(outcomeNames))));
			for (let i = 0; i < cases / 4; i++)
				check(aimedEnum(validReply(pick(outcomeNames)), replyTable));
			for (const frame of edgeFrames(replyTable)) check(frame);
			// At the reply's limit and one past it: an ok body as long as the frame allows, 65536 bytes.
			const longest = encodeReply({
				outcome: "ok",
				id: 9,
				message: { body: new Uint8Array(maxReplyBody - 2 - 2 - 64), dpopNonce: "A".repeat(64) },
			});
			expect(longest.length).toBe(headerLength + maxReplyBody);
			check(longest);
			const past = new Uint8Array(longest.length + 1);
			past.set(longest);
			new DataView(past.buffer).setUint32(6, maxReplyBody + 1);
			check(past);
			expect(decodeReply(past)).toEqual({ ok: false, error: "length", id: 9 });
			expect(counted, first()).toMatchObject({ threw: 0, disagreed: 0, nonCanonical: 0 });
			expect(counted.accepted).toBeGreaterThan(0);
			for (const code of Object.keys(wireErrors))
				expect(codes.get(code) ?? 0, code).toBeGreaterThan(3);
		},
		Math.max(5000, cases * 4),
	);
});

describe("frames written apart from the codec", () => {
	it("are read as written, each field at any length its spec allows, at its least and its most, and refused one past", () => {
		for (const kind of kinds) {
			const spec = requests[kind];
			const fields = spec.fields as readonly FieldSpec[];
			// The least and the most each field allows, then lengths between: read field by field as written.
			for (const pickLength of [
				(f: FieldSpec) => f.min,
				(f: FieldSpec) => f.max,
				(f: FieldSpec) => f.min + int(Math.min(f.max, 600) - f.min + 1),
			]) {
				const drawn = fields.map((f) => {
					const n = pickLength(f);
					return f.type === "jws" && n > 0 && n < 5 ? exact(f, 5) : exact(f, n);
				});
				const id = int(2 ** 32);
				const frame = frameOf(
					spec.code,
					id,
					drawn.map((d) => d.bytes),
				);
				const read = decodeRequest(frame);
				expect(read, kind).toEqual({
					ok: true,
					value: {
						kind,
						id,
						message: Object.fromEntries(fields.map((f, i) => [f.name, drawn[i]?.value])),
					},
				});
				expect(
					Buffer.from(encodeRequest(kind, id, (read.ok && read.value.message) as never)).equals(
						Buffer.from(frame),
					),
				).toBe(true);
			}
			// Each field one past its most, the others at their least: fieldLength, by the decoder and the encoder alike.
			for (const [i, f] of fields.entries()) {
				if (f.type === "enum") continue;
				const drawn = fields.map((g, j) =>
					j === i
						? exact(g, g.max + 1)
						: exact(g, g.type === "jws" && g.min > 0 ? Math.max(g.min, 5) : g.min),
				);
				const frame = frameOf(
					spec.code,
					3,
					drawn.map((d) => d.bytes),
				);
				if (frame.length - headerLength > maxRequestBody) continue;
				expect(decodeRequest(frame), `${kind} ${f.name}`).toEqual({
					ok: false,
					error: "fieldLength",
					id: 3,
				});
				expect(() =>
					encodeRequest(
						kind,
						3,
						Object.fromEntries(fields.map((g, j) => [g.name, drawn[j]?.value])) as never,
					),
				).toThrow(`wire: ${f.name} fieldLength`);
			}
		}
	});

	it("are read as written for replies too, each field at its least, its most and between, and refused one past", () => {
		for (const outcome of Object.keys(outcomes) as (keyof typeof outcomes)[]) {
			const fields = replies[outcome] as readonly FieldSpec[];
			for (const pickLength of [
				(f: FieldSpec) => f.min,
				(f: FieldSpec) => f.max,
				(f: FieldSpec) => f.min + int(Math.min(f.max, 600) - f.min + 1),
			]) {
				const drawn = fields.map((f) => exact(f, pickLength(f)));
				const id = int(2 ** 32);
				const frame = frameOf(
					outcomes[outcome],
					id,
					drawn.map((d) => d.bytes),
				);
				const read = decodeReply(frame);
				expect(read, outcome).toEqual({
					ok: true,
					value: {
						outcome,
						id,
						message: Object.fromEntries(fields.map((f, i) => [f.name, drawn[i]?.value])),
					},
				});
				expect(
					Buffer.from(encodeReply((read.ok && read.value) as never)).equals(Buffer.from(frame)),
				).toBe(true);
			}
			for (const [i, f] of fields.entries()) {
				if (f.type === "enum") continue;
				const drawn = fields.map((g, j) => exact(g, j === i ? g.max + 1 : g.min));
				const frame = frameOf(
					outcomes[outcome],
					3,
					drawn.map((d) => d.bytes),
				);
				if (frame.length - headerLength > maxReplyBody) continue;
				expect(decodeReply(frame), `${outcome} ${f.name}`).toEqual({
					ok: false,
					error: "fieldLength",
					id: 3,
				});
			}
		}
	});
});

describe("a stream cut anywhere", () => {
	it("hands on each frame whole, however the stream is cut", () => {
		const frames = kinds.map((k) => validFrame(k));
		const stream = Uint8Array.from(frames.flatMap((f) => [...f]));
		const got: Uint8Array[] = [];
		const feed = frameSplitter(
			maxRequestBody,
			(f) => got.push(f),
			() => {
				throw new Error("no error expected");
			},
		);
		for (let at = 0; at < stream.length; ) {
			const step = 1 + int(64);
			feed(stream.subarray(at, at + step));
			at += step;
		}
		expect(got.map((f) => Buffer.from(f).toString("hex"))).toEqual(
			frames.map((f) => Buffer.from(f).toString("hex")),
		);
	});

	/** The whole stream read at once: its frames, then the error and id it stops at, none where none. */
	function referenceSplit(stream: Uint8Array, max: number) {
		const frames: string[] = [];
		for (let at = 0; stream.length - at >= headerLength; ) {
			const view = new DataView(stream.buffer, stream.byteOffset + at, headerLength);
			if (stream[at] !== 1) return { frames, error: ["version", 0] as const };
			const length = view.getUint32(6);
			if (length > max) return { frames, error: ["length", view.getUint32(2)] as const };
			if (stream.length - at < headerLength + length) break;
			frames.push(Buffer.from(stream.subarray(at, at + headerLength + length)).toString("hex"));
			at += headerLength + length;
		}
		return { frames, error: undefined };
	}

	it("hands on the frames and the one error the whole stream reads to, however hostile and however cut, at either side's limit", () => {
		for (const [max, make] of [
			[maxRequestBody, () => validFrame(pick(kinds))],
			[maxReplyBody, () => validReply(pick(Object.keys(outcomes) as (keyof typeof outcomes)[]))],
		] as const) {
			let stopped = 0;
			for (let i = 0; i < Math.max(50, Math.floor(cases / 10)); i++) {
				// Frames, some mutated, one perhaps with a wrong version or length, joined as a peer sends them.
				const parts = Array.from({ length: 1 + int(5) }, () =>
					int(3) === 0 ? mutate(make()) : make(),
				);
				// Now and then a bare header last: a wrong version, a length past the limit, or none.
				if (int(3) === 0) {
					const bare = new Uint8Array(headerLength);
					bare[0] = pick([1, 2]);
					new DataView(bare.buffer).setUint32(6, pick([0, max + 1, 5]));
					parts.push(bare);
				}
				const stream = Uint8Array.from(parts.flatMap((p) => [...p]));
				const expected = referenceSplit(stream, max);
				const got: string[] = [];
				const errors: (readonly [string, number])[] = [];
				const feed = frameSplitter(
					max,
					(f) => got.push(Buffer.from(f).toString("hex")),
					(e, id) => errors.push([e, id]),
				);
				for (let at = 0; at < stream.length; ) {
					const step = 1 + int(int(2) === 0 ? 8 : 4096);
					feed(stream.subarray(at, at + step));
					at += step;
				}
				expect(got).toEqual(expected.frames);
				expect(errors).toEqual(expected.error ? [expected.error] : []);
				if (expected.error) stopped++;
				for (const f of got) expect(f.length / 2).toBeLessThanOrEqual(headerLength + max);
			}
			expect(stopped).toBeGreaterThan(0);
		}
	});

	it("hands on a frame whose body is its side's limit, and stops at one past, at either side's limit", () => {
		for (const max of [maxRequestBody, maxReplyBody]) {
			const at = frameOf(1, 5, []);
			const whole = new Uint8Array(headerLength + max);
			whole.set(at.subarray(0, headerLength));
			new DataView(whole.buffer).setUint32(6, max);
			const past = new Uint8Array(headerLength + max + 1);
			past.set(at.subarray(0, headerLength));
			new DataView(past.buffer).setUint32(6, max + 1);
			const got: number[] = [];
			const errors: (readonly [string, number])[] = [];
			const feed = frameSplitter(
				max,
				(f) => got.push(f.length),
				(e, id) => errors.push([e, id]),
			);
			feed(whole);
			feed(past);
			expect(got).toEqual([headerLength + max]);
			expect(errors).toEqual([["length", 5]]);
		}
	});

	it("stops at a header with a wrong version or length, once, without waiting for its body", () => {
		const errors: string[] = [];
		const feed = frameSplitter(
			maxRequestBody,
			() => undefined,
			(e) => errors.push(e),
		);
		const bad = validFrame("token");
		new DataView(bad.buffer).setUint32(6, maxRequestBody + 1);
		feed(bad.subarray(0, headerLength));
		// Told at the header alone, its body never waited for.
		expect(errors).toEqual(["length"]);
		feed(validFrame("token"));
		expect(errors).toEqual(["length"]);
	});
});
