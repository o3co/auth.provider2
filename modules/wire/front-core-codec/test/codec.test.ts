import {
	type FieldSpec,
	headerLength,
	maxRequestBody,
	type RequestKind,
	requests,
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
	const latin1 = String.fromCharCode(...value);
	switch (spec.type) {
		case "bytes":
			return true;
		case "enum":
			return (value[0] ?? 0) < (spec.values ?? 0);
		case "visible":
			return value.every((c) => c >= 0x21 && c <= 0x7e);
		case "b64url":
		case "jws":
			return pattern[spec.type].test(latin1);
		case "utf8": {
			const text = Buffer.from(value).toString("utf8");
			const plain = [...text].every((ch) => (ch.codePointAt(0) ?? 0) >= 0x20 && ch !== "\u007f");
			return Buffer.from(text, "utf8").equals(Buffer.from(value)) && plain;
		}
	}
}
function referenceAccepts(bytes: Uint8Array): boolean {
	const a = Array.from(bytes);
	if (a.length < headerLength || a[0] !== 1) return false;
	const length = (a[6] ?? 0) * 2 ** 24 + (a[7] ?? 0) * 2 ** 16 + (a[8] ?? 0) * 2 ** 8 + (a[9] ?? 0);
	if (length > maxRequestBody || a.length !== headerLength + length) return false;
	const spec = Object.values(requests).find((r) => r.code === a[1]);
	if (!spec) return false;
	let at = headerLength;
	for (const f of spec.fields as readonly FieldSpec[]) {
		if (at + 2 > a.length) return false;
		const n = (a[at] ?? 0) * 256 + (a[at + 1] ?? 0);
		at += 2;
		if (at + n > a.length || n < f.min || n > f.max) return false;
		if (n > 0 && !referenceSyntax(f, a.slice(at, at + n))) return false;
		at += n;
	}
	return at === a.length;
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
	it("never throws, agrees with the reference decoder, takes only canonical frames, and rejects by a known code", () => {
		const counted = { cases: 0, accepted: 0, disagreed: 0, nonCanonical: 0, threw: 0 };
		const check = (bytes: Uint8Array) => {
			counted.cases++;
			let read: ReturnType<typeof decodeRequest>;
			try {
				read = decodeRequest(bytes);
			} catch {
				counted.threw++;
				return;
			}
			if (read.ok !== referenceAccepts(bytes)) counted.disagreed++;
			if (read.ok) {
				counted.accepted++;
				const again = encodeRequest(read.value.kind, read.value.id, read.value.message as never);
				if (!Buffer.from(again).equals(Buffer.from(bytes))) counted.nonCanonical++;
			} else expect(read.error in wireErrors).toBe(true);
		};
		for (let i = 0; i < cases; i++) check(randomBytes(int(200)));
		for (let i = 0; i < cases; i++) check(mutate(validFrame(pick(kinds))));
		expect(counted).toMatchObject({ threw: 0, disagreed: 0, nonCanonical: 0 });
		expect(counted.accepted).toBeGreaterThan(0);
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
		feed(validFrame("token"));
		expect(errors).toEqual(["length"]);
	});
});
