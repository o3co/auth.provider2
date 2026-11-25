import { describe, expect, it } from "vitest";
import {
	headerLength,
	maxRequestBody,
	outcomes,
	refusals,
	replies,
	requests,
	version,
	wireErrors,
} from "../src/contract.ts";

const kinds = Object.values(requests);

describe("the requests the Core opens to the Front", () => {
	it("gives each kind a code of its own, one byte, never 0", () => {
		const codes = kinds.map((k) => k.code);
		expect(new Set(codes).size).toBe(codes.length);
		for (const code of codes) expect(code > 0 && code < 256, String(code)).toBe(true);
		// The first key's old continuation and finish (0x08, 0x09) are not given again.
		expect((codes as readonly number[]).filter((code) => code === 0x08 || code === 0x09)).toEqual(
			[],
		);
	});

	it("names each field once in its kind, with a length range a u16 holds", () => {
		for (const [name, kind] of Object.entries(requests)) {
			const names = kind.fields.map((f) => f.name);
			expect(new Set(names).size, name).toBe(names.length);
			for (const f of kind.fields) {
				expect(f.min >= 0 && f.min <= f.max && f.max <= 0xffff, `${name}.${f.name}`).toBe(true);
				if (f.type === "enum")
					expect([f.min, f.max, ((f as { values?: number }).values ?? 0) > 0]).toEqual([
						1,
						1,
						true,
					]);
			}
		}
	});

	it("fits every kind's fields at their greatest within the body's limit, so the limit refuses no well-formed request", () => {
		for (const [name, kind] of Object.entries(requests)) {
			expect(
				kind.fields.reduce((n, f) => n + 2 + f.max, 0),
				name,
			).toBeLessThanOrEqual(maxRequestBody);
		}
	});
});

describe("the frame and its answers", () => {
	it("starts each frame with version 1 in a header of ten bytes", () => {
		expect([version, headerLength]).toEqual([1, 10]);
	});

	it("tells each rejection by a code of its own, never 0, and each outcome by one", () => {
		const codes = Object.values(wireErrors);
		expect(new Set(codes).size).toBe(codes.length);
		expect((codes as readonly number[]).includes(0)).toBe(false);
		expect(Object.keys(outcomes)).toEqual(Object.keys(replies));
		expect(new Set(Object.values(outcomes)).size).toBe(3);
	});

	it("names each refusal once, within what its enum field holds", () => {
		expect(new Set(refusals).size).toBe(refusals.length);
		expect(refusals.length).toBeLessThan((replies.refused[0] as { values: number }).values);
	});

	it("keeps each refusal's code, a word added going last", () => {
		const code = (word: (typeof refusals)[number]) => refusals.indexOf(word) + 1;
		expect([code("invalid_request"), code("server_error"), code("too_many_attempts")]).toEqual([
			1, 11, 13,
		]);
		expect([code("login_required"), code("invalid_request_uri"), code("invalid_target")]).toEqual([
			14, 15, 16,
		]);
	});

	it("holds every word frozen", () => {
		for (const words of [
			requests,
			wireErrors,
			outcomes,
			replies,
			refusals,
			...kinds,
			...kinds.map((k) => k.fields),
		]) {
			expect(Object.isFrozen(words)).toBe(true);
		}
	});
});
