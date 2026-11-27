import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { continuations } from "../src/contract.ts";

// C9: the readers of what the screen seals to the Core in a continuation, and of the body it signs.
const seed = Number(process.env.WIRE_FUZZ_SEED ?? 20261127);
const numRuns = Number(process.env.WIRE_FUZZ_CASES ?? 2000);
// The time a run takes grows with its cases.
vi.setConfig({ testTimeout: Math.max(5000, numRuns * 4) });
const sealed = continuations.sealed;
const bodyStages = Object.keys(continuations.bodies);
const utf8 = (text: string) => Buffer.byteLength(text, "utf8");

/** A credential id in its one spelling: 1 to 1023 bytes, unpadded base64url. */
const credentialId = fc
	.uint8Array({ minLength: 1, maxLength: 1023, size: "max" })
	.map((b) => Buffer.from(b).toString("base64url"));
/** A label: 1 to 64 code points, none a control, format, surrogate or line separator; wide ones among them. */
const label = fc
	.array(fc.constantFrom("a", "Z", " ", "é", "名", "😀", "\u{10ffff}", '"', "\\"), {
		minLength: 1,
		maxLength: 64,
	})
	.map((cs) => cs.join(""));
const sig = fc
	.tuple(
		fc.string({ unit: fc.constantFrom(..."ABCabc019-_"), minLength: 85, maxLength: 85 }),
		fc.constantFrom("A", "Q", "g", "w"),
	)
	.map(([a, b]) => `${a}${b}`);
const bodyOf = (stage: (typeof sealed)[number]) =>
	stage === "delete"
		? credentialId.map((id) => ({ credential_id: id }))
		: fc.tuple(credentialId, label).map(([id, l]) => ({ credential_id: id, label: l }));
const sealedCase = fc
	.constantFrom(...sealed)
	.chain((stage) => fc.tuple(fc.constant(stage), bodyOf(stage), sig));
/** A text padded again with spaces to plainBytes of UTF-8, where it fits. */
const repad = (t: string) => {
	const content = t.trimEnd();
	const pad = continuations.plainBytes - utf8(content);
	return pad >= 0 ? `${content}${" ".repeat(pad)}` : content;
};
/** A canonical text written apart from the wire's: sorted members, no space. */
const canonical = (value: Record<string, unknown>): string =>
	`{${Object.keys(value)
		.sort()
		.map(
			(k) =>
				`${JSON.stringify(k)}:${typeof value[k] === "object" ? canonical(value[k] as Record<string, unknown>) : JSON.stringify(value[k])}`,
		)
		.join(",")}}`;

describe("a sealed continuation's plaintext", () => {
	it("is its canonical text padded with spaces to plainBytes of UTF-8, read back as it was, and by no other stage", () => {
		fc.assert(
			fc.property(sealedCase, ([stage, body, s]) => {
				const text = continuations.plainOf(stage, body, s);
				expect(text).toBe(
					`${canonical({ body, sig: s })}${" ".repeat(continuations.plainBytes - utf8(canonical({ body, sig: s })))}`,
				);
				expect(utf8(text ?? "")).toBe(continuations.plainBytes);
				expect(continuations.readPlain(stage, text as string)).toEqual({ body, sig: s });
				const other = sealed.find((x) => x !== stage) as (typeof sealed)[number];
				if (stage === "rename")
					expect(continuations.readPlain(other, text as string)).toBeUndefined();
			}),
			{ seed, numRuns },
		);
	});

	it("is read only where plainOf writes that very text: any text it reads, plainOf gives back", () => {
		const mutations: readonly ((
			text: string,
			body: Record<string, unknown>,
			s: string,
		) => string)[] = [
			// A member named twice; an escape for a letter; members out of order; a space inside; a tab or
			// a newline in the padding; a __proto__ member; cut or longer by one; one byte changed. A change
			// of the content is padded again to the length, so it is the canonical and the shape that refuse it.
			(t) => repad(t.replace('"sig":', '"sig":"x","sig":')),
			(t) => repad(t.replace('"sig"', '"\\u0073ig"')),
			(_, b, s) => repad(`{"sig":${JSON.stringify(s)},"body":${canonical(b)}}`),
			(t) => repad(t.replace('{"body":', '{ "body":')),
			(t) => `${t.trimEnd()}\t${" ".repeat(utf8(t) - utf8(t.trimEnd()) - 1)}`,
			(t) => `${t.trimEnd()}\n${" ".repeat(utf8(t) - utf8(t.trimEnd()) - 1)}`,
			(t) => repad(t.replace('{"body":', '{"__proto__":{},"body":')),
			(t) => t.slice(0, -1),
			(t) => `${t} `,
			(t) => repad(t.replace('"credential_id":"', '"credential_id":"!')),
			// A space before the text, the padding one shorter; a signature one character longer or shorter.
			(t) => ` ${t.slice(0, -1)}`,
			(t, _, s) => repad(t.replace(s, `${s}A`)),
			(t, _, s) => repad(t.replace(s, s.slice(1))),
			// The signature's last character with a spare bit set: the same length, another spelling.
			(t, _, s) => t.replace(s, `${s.slice(0, -1)}B`),
		];
		const reached = new Set<number>();
		fc.assert(
			fc.property(sealedCase, fc.nat(mutations.length - 1), ([stage, body, s], m) => {
				const text = continuations.plainOf(stage, body, s) as string;
				const mutated = (
					mutations[m] as (t: string, b: Record<string, unknown>, s: string) => string
				)(text, body, s);
				const read = continuations.readPlain(stage, mutated);
				if (read !== undefined)
					expect(continuations.plainOf(stage, read.body, read.sig)).toBe(mutated);
				// Each change named is refused: no text but the one written is read.
				if (mutated !== text) expect(read, `mutation ${m}`).toBeUndefined();
				// A content change padded again is of the length, so the length is not what refuses it.
				if (utf8(mutated) === continuations.plainBytes) reached.add(m);
			}),
			{ seed, numRuns },
		);
		for (const m of [0, 1, 2, 3, 4, 5, 6, 9])
			expect(reached, `mutation ${m} at the length`).toContain(m);
	});

	it("reads nothing, never throwing, from text of any other form", () => {
		fc.assert(
			fc.property(
				fc.constantFrom(...sealed),
				fc.oneof(fc.string(), fc.string({ unit: "binary" }), fc.json()),
				(stage, text) => {
					const padded = text.padEnd(continuations.plainBytes, " ");
					for (const t of [text, padded]) {
						const read = continuations.readPlain(stage, t);
						if (read !== undefined)
							expect(continuations.plainOf(stage, read.body, read.sig)).toBe(t);
					}
				},
			),
			{ seed, numRuns },
		);
	});
});

describe("the text a continuation's body hash covers", () => {
	/** A credential id's one spelling and length, read by Buffer apart from the wire. */
	const anId = (v: unknown) =>
		typeof v === "string" &&
		/^[A-Za-z0-9_-]+$/.test(v) &&
		Buffer.from(v, "base64url").toString("base64url") === v &&
		Buffer.from(v, "base64url").length >= 1 &&
		Buffer.from(v, "base64url").length <= 1023;
	/** A label: 1 to 64 code points, none a control, format, surrogate or line or paragraph separator. */
	const aLabel = (v: unknown) =>
		typeof v === "string" &&
		[...v].length >= 1 &&
		[...v].length <= 64 &&
		![...v].some((c) => /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(c));
	const exactly = (v: unknown, keys: readonly string[]) => {
		if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
		const own = Object.keys(v).sort();
		return own.length === keys.length && own.every((k, n) => k === keys[n]);
	};
	/** Whether a stage's body is of its shape, decided here apart from the wire's schemas. */
	const shaped = (stage: string, b: unknown) => {
		const o = b as Record<string, unknown>;
		if (stage === "delete") return exactly(b, ["credential_id"]) && anId(o.credential_id);
		if (stage === "rename")
			return exactly(b, ["credential_id", "label"]) && anId(o.credential_id) && aLabel(o.label);
		if (stage === "sign-up") return exactly(b, []);
		return false;
	};

	it("is the body's canonical text for a stage with a body of its shape alone, for any stage name and any body, decided apart, never throwing", () => {
		const stage = fc.oneof(
			fc.constantFrom(...bodyStages, "register", "__proto__", "constructor", "toString", ""),
			fc.string(),
		);
		// Ids at and past their bounds: 1023 bytes (1364 characters) and 1024 (1366); labels at 64 and 65 code points, or holding a format character.
		const id = fc.oneof(
			credentialId,
			fc.constantFrom(
				Buffer.alloc(1023, 1).toString("base64url"),
				Buffer.alloc(1024, 1).toString("base64url"),
				`${Buffer.alloc(3, 1).toString("base64url")}=`,
				"AQ",
				"AR",
				"",
			),
		);
		const anyLabel = fc.oneof(
			label,
			fc.constantFrom(
				"😀".repeat(64),
				"😀".repeat(65),
				"a\u200bb",
				"a\u2028b",
				"a\u2029b",
				"a\u0001b",
				"a\ud800b",
				"",
				"a".repeat(64),
			),
		);
		const body = fc.oneof(
			id.map((credential_id) => ({ credential_id })),
			fc
				.tuple(id, anyLabel, fc.boolean())
				.map(([credential_id, l, labelFirst]) =>
					labelFirst ? { label: l, credential_id } : { credential_id, label: l },
				),
			fc.constant({}),
			fc.jsonValue(),
			fc.record({ credential_id: fc.string(), label: fc.string() }),
		);
		const seen = { shaped: 0, refused: 0 };
		fc.assert(
			fc.property(stage, body, (st, b) => {
				const text = continuations.bodyText(st, b);
				expect(text !== undefined, `${st} ${JSON.stringify(b).slice(0, 80)}`).toBe(shaped(st, b));
				if (text !== undefined) {
					seen.shaped++;
					expect(text).toBe(canonical(b as Record<string, unknown>));
				} else seen.refused++;
			}),
			{ seed, numRuns },
		);
		for (const [what, n] of Object.entries(seen)) expect(n, what).toBeGreaterThan(0);
	});
});
