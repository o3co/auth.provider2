import { overHttp } from "@mod/front-core-wire";
import { payloads } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { type AnswerForm, answers } from "../src/answers.ts";
import { base64url, digest } from "../src/bytes.ts";
import { screenKeys } from "../src/keys.ts";

const compact = "eyJhbGciOiJFUzI1NiJ9.eyJ2IjoxfQ.c2ln";

/** A body of each form, as the Core answers it. */
async function bodies() {
	const enc = (await screenKeys()).eEnc;
	const ct = base64url(crypto.getRandomValues(new Uint8Array(40)));
	const bytes32 = await digest("thirty-two bytes");
	return {
		enc,
		ct,
		bytes32,
		of: {
			authorization: { statement: compact, challenge: bytes32, create: true },
			statement: { statement: compact },
			sealed: { sealed: { enc, ct } },
			nonce: { nonce: bytes32 },
		} satisfies Record<AnswerForm, unknown>,
	};
}

describe("answers.read", () => {
	it("reads each form to the value the SDK's steps take", async () => {
		const b = await bodies();
		expect(answers.read("authorization", b.of.authorization)).toEqual({
			statement: compact,
			create: true,
		});
		expect(answers.read("statement", b.of.statement)).toBe(compact);
		expect(answers.read("nonce", b.of.nonce)).toBe(b.bytes32);
		const sealed = answers.read("sealed", b.of.sealed);
		expect(sealed?.enc).toHaveLength(65);
		expect(base64url(sealed?.enc ?? new Uint8Array())).toBe(b.enc);
		expect(base64url(sealed?.ct ?? new Uint8Array())).toBe(b.ct);
	});

	it("gives values of its own, frozen: changing the body after reads nothing", async () => {
		const b = await bodies();
		const body = structuredClone(b.of.authorization);
		const read = answers.read("authorization", body);
		body.statement = "x.y.z";
		expect(read).toEqual({ statement: compact, create: true });
		expect(Object.isFrozen(read)).toBe(true);
		expect(Object.isFrozen(answers.read("sealed", b.of.sealed))).toBe(true);
		// The challenge is not handed on: the screen computes it from T.
		expect(read).not.toHaveProperty("challenge");
	});

	it("reads a sealed answer wrapped as the wire gives it, never the bare enc and ct", async () => {
		const b = await bodies();
		expect(answers.read("sealed", { sealed: { enc: b.enc, ct: b.ct } })).toBeDefined();
		expect(answers.read("sealed", { enc: b.enc, ct: b.ct })).toBeUndefined();
	});

	it("reads none for a body of another shape, another form, a refusal, or a value no object", async () => {
		const b = await bodies();
		const none: [AnswerForm, unknown][] = [
			["statement", { statement: "not a jws" }],
			["statement", { statement: compact, extra: 1 }],
			["statement", b.of.nonce],
			["nonce", { nonce: "short" }],
			["nonce", b.of.statement],
			["authorization", { statement: compact, create: true }],
			["authorization", { ...b.of.authorization, create: "yes" }],
			["sealed", { sealed: { enc: b.enc, ct: b.ct, extra: 1 } }],
			["sealed", { sealed: { enc: b.enc, ct: b.ct }, extra: 1 }],
			["sealed", { sealed: { enc: "A".repeat(87), ct: b.ct } }],
			["sealed", { sealed: { enc: b.enc, ct: `${b.ct}=` } }],
			["sealed", { sealed: { enc: b.enc, ct: "AAAA" } }],
			["sealed", b.of.statement],
		];
		for (const [form, body] of none)
			expect(answers.read(form, body), `${form} ${JSON.stringify(body)}`).toBeUndefined();
		const refusal = { error: "invalid_request", error_description: "no" };
		for (const form of Object.keys(b.of) as AnswerForm[]) {
			expect(answers.read(form, refusal), form).toBeUndefined();
			for (const value of [null, [], "text", 1, undefined])
				expect(answers.read(form, value), `${form} ${String(value)}`).toBeUndefined();
		}
	});

	it("reads an enc of the point's form though it is no point of the curve: the opening sees that, not this read", async () => {
		const b = await bodies();
		const offCurve = `B${"A".repeat(86)}`;
		const read = answers.read("sealed", { sealed: { enc: offCurve, ct: b.ct } });
		expect(read?.enc).toHaveLength(65);
		// Another first byte is not the point's form at all.
		expect(
			answers.read("sealed", { sealed: { enc: `C${"A".repeat(86)}`, ct: b.ct } }),
		).toBeUndefined();
	});

	it("reads none for padded base64url anywhere", async () => {
		const b = await bodies();
		expect(answers.read("nonce", { nonce: `${b.bytes32}=` })).toBeUndefined();
		expect(
			answers.read("authorization", { ...b.of.authorization, challenge: `${b.bytes32}=` }),
		).toBeUndefined();
	});

	it("reads none for a form it does not know, an object's own names among them", async () => {
		const b = await bodies();
		for (const form of ["constructor", "__proto__", "toString", "hasOwnProperty", "", "Sealed"])
			expect(answers.read(form, b.of.statement), form).toBeUndefined();
	});

	it("reads every form sdk-core-wire holds, and every form front-core-wire names, as text", async () => {
		const b = await bodies();
		expect(Object.keys(payloads.answers).sort()).toEqual(Object.keys(b.of).sort());
		for (const form of Object.keys(payloads.answers))
			expect(answers.read(form, b.of[form as AnswerForm]), form).toBeDefined();
		const named = Object.values(overHttp.operations).flatMap((http) =>
			http.answer === undefined
				? []
				: typeof http.answer === "string"
					? [http.answer]
					: http.answer.forms,
		);
		for (const form of named)
			expect(answers.read(form, b.of[form as AnswerForm]), form).toBeDefined();
	});
});
