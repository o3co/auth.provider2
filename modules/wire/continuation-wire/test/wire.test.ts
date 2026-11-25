import { describe, expect, it } from "vitest";
import { continuations } from "../src/contract.ts";

const sig = `${"A".repeat(85)}A`;
const bytes = (text: string) => Buffer.byteLength(text);

describe("a statement's continuation", () => {
	it("signs each stage apart, the same bytes for register as before its stages were named", () => {
		expect(continuations.stages).toEqual(["register", "delete", "rename"]);
		const inputs = continuations.stages.map((stage) => continuations.of(stage, "h", 1, "b"));
		expect(new Set(inputs).size).toBe(3);
		expect(continuations.of("register", "h", 1, "b")).toBe(
			'{"body":"b","h":"h","seq":1,"stage":"register"}',
		);
		expect(continuations.signature).toEqual({
			alg: "ES256",
			form: "r||s",
			over: "UTF-8 of continuations.of",
		});
	});

	it("reads a delete's and a rename's body strict: a credential id in one spelling, a label's text", () => {
		const { delete: del, rename } = continuations.bodies;
		expect(del.safeParse({ credential_id: "AQID" }).success).toBe(true);
		expect(del.safeParse({ credential_id: "AQID", label: "x" }).success).toBe(false);
		expect(rename.safeParse({ credential_id: "AQID", label: "Laptop" }).success).toBe(true);
		for (const label of ["", "x".repeat(65), "a‮b", "a\nb", "\ud800"])
			expect(
				rename.safeParse({ credential_id: "AQID", label }).success,
				JSON.stringify(label),
			).toBe(false);
		for (const id of ["A", "AB", "A=", "a+b", "A".repeat(1365)])
			expect(del.safeParse({ credential_id: id }).success, id).toBe(false);
	});

	it("gives the text a body's hash covers, for a stage with a body of its shape alone", () => {
		expect(continuations.bodyText("rename", { label: "鍵", credential_id: "AQID" })).toBe(
			'{"credential_id":"AQID","label":"鍵"}',
		);
		expect(continuations.bodyText("delete", { credential_id: "AQID" })).toBe(
			'{"credential_id":"AQID"}',
		);
		// A register's hash covers the response's text as received: no body of its shape here.
		expect(continuations.bodyText("register", {})).toBeUndefined();
		expect(continuations.bodyText("delete", { credential_id: "A=" })).toBeUndefined();
		for (const stage of ["constructor", "__proto__", "toString", ""])
			expect(continuations.bodyText(stage, {}), stage).toBeUndefined();
	});

	it("holds its words frozen", () => {
		for (const words of [
			continuations,
			continuations.stages,
			continuations.sealed,
			continuations.signature,
			continuations.bodies,
		])
			expect(Object.isFrozen(words)).toBe(true);
	});
});

describe("a sealed continuation's body (V24)", () => {
	it("seals a delete's and a rename's body with its signature, padded with spaces to one length, and reads it back", () => {
		expect(continuations.sealed).toEqual(["delete", "rename"]);
		const deleted = continuations.plainOf("delete", { credential_id: "AQID" }, sig);
		if (deleted === undefined) throw new Error("no plain");
		expect(bytes(deleted)).toBe(continuations.plainBytes);
		expect(deleted.trimEnd()).toBe(`{"body":{"credential_id":"AQID"},"sig":"${sig}"}`);
		expect(continuations.readPlain("delete", deleted)).toEqual({
			body: { credential_id: "AQID" },
			sig,
		});
		const renamed = continuations.plainOf("rename", { credential_id: "AQID", label: "鍵" }, sig);
		expect(renamed && continuations.readPlain("rename", renamed)).toEqual({
			body: { credential_id: "AQID", label: "鍵" },
			sig,
		});
	});

	it("fits the worst rename: a credential id of 1023 bytes and 64 characters escaped longest", () => {
		const worst = { credential_id: "A".repeat(1364), label: "😀".repeat(64) };
		const plain = continuations.plainOf("rename", worst, sig);
		expect(plain && bytes(plain)).toBe(continuations.plainBytes);
		expect(
			continuations.plainOf("rename", { ...worst, credential_id: "A".repeat(1365) }, sig),
		).toBeUndefined();
	});

	it("reads no text of another length, not canonical, of another stage's body or a signature of no shape", () => {
		const plain = continuations.plainOf("delete", { credential_id: "AQID" }, sig) ?? "";
		const pad = (text: string) => `${text}${" ".repeat(continuations.plainBytes - bytes(text))}`;
		for (const text of [
			plain.slice(0, -1),
			`${plain} `,
			pad(`{"sig":"${sig}","body":{"credential_id":"AQID"}}`),
			pad(`{"body":{"credential_id":"AQID"}, "sig":"${sig}"}`),
			pad(`{"body":{"credential_id":"AQID"},"sig":"${sig.slice(1)}"}`),
			pad(`{"body":{"credential_id":"AQID","label":"x"},"sig":"${sig}"}`),
		])
			expect(continuations.readPlain("delete", text), text.trimEnd()).toBeUndefined();
		expect(continuations.plainOf("delete", { credential_id: "AQID" }, "x")).toBeUndefined();
	});

	it("binds a sealed body to its stage, statement and sequence", () => {
		const aads = [
			continuations.aad("delete", "h", 1),
			continuations.aad("rename", "h", 1),
			continuations.aad("delete", "g", 1),
			continuations.aad("delete", "h", 2),
		];
		expect(new Set(aads).size).toBe(4);
		expect(aads[0]).toBe('{"h":"h","purpose":"continuation/delete","seq":1}');
	});
});
