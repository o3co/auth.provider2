import { describe, expect, it } from "vitest";
import {
	instructionSkew,
	resetFaults,
	resetInstruction,
	resetLifetime,
	resetRefusal,
} from "../src/contract.ts";

const instruction = {
	v: 1,
	installation: "inst-1",
	subject: "sub-1",
	action: "reset",
	kg: 2,
	id: "A".repeat(22),
	iat: 1_700_000_000,
	exp: 1_700_000_600,
};
const reads = (value: unknown) => resetInstruction.safeParse(value).success;

describe("a reset instruction", () => {
	it("reads the installation, subject, action, key generation, id and times", () => {
		expect(resetInstruction.parse(instruction)).toEqual(instruction);
	});

	it("lives no longer than its lifetime, and is issued before it expires", () => {
		expect([resetLifetime, instructionSkew]).toEqual([600, 60]);
		expect(reads({ ...instruction, exp: instruction.iat + 1 })).toBe(true);
		expect(reads({ ...instruction, exp: instruction.iat + 601 })).toBe(false);
		expect(reads({ ...instruction, exp: instruction.iat })).toBe(false);
		expect(reads({ ...instruction, exp: instruction.iat - 1 })).toBe(false);
	});

	it("takes an id of 22 to 43 base64url characters alone, so it never holds the op's separator", () => {
		for (const id of ["A".repeat(22), "-_09azAZ".repeat(5).slice(0, 43)])
			expect(reads({ ...instruction, id }), id).toBe(true);
		for (const id of [
			"A".repeat(21),
			"A".repeat(44),
			`${"A".repeat(21)}:`,
			`${"A".repeat(21)}=`,
			`${"A".repeat(21)}+`,
		])
			expect(reads({ ...instruction, id }), id).toBe(false);
	});

	it("refuses another action, another version, a field it does not know, and a time or generation that is no whole number", () => {
		for (const change of [
			{ action: "clear" },
			{ v: 2 },
			{ extra: 1 },
			{ kg: -1 },
			{ kg: 1.5 },
			{ iat: 1.5 },
			{ installation: "" },
			{ subject: "" },
		])
			expect(reads({ ...instruction, ...change }), JSON.stringify(change)).toBe(false);
		const { installation: _, ...without } = instruction;
		expect(reads(without)).toBe(false);
	});
});

describe("a reset not placed", () => {
	it("names its faults in the order the rule checks them", () => {
		expect(resetFaults).toEqual([
			"shape",
			"set",
			"signature",
			"installation",
			"subject",
			"op",
			"generation",
			"time",
		]);
		expect(Object.isFrozen(resetFaults)).toBe(true);
	});

	it("makes and reads an invalid answer with its fault, and a conflict", () => {
		for (const fault of resetFaults) {
			const answer = resetRefusal.invalid(fault);
			expect(answer).toEqual({ v: 1, result: "invalid", fault });
			expect(resetRefusal.schema.parse(answer)).toEqual(answer);
		}
		expect(resetRefusal.schema.parse(resetRefusal.conflict())).toEqual({
			v: 1,
			result: "conflict",
		});
	});

	it("refuses an answer of another result, an unknown fault, or a field it does not know", () => {
		for (const answer of [
			{ v: 1, result: "accepted" },
			{ v: 1, result: "invalid", fault: "late" },
			{ v: 1, result: "invalid" },
			{ v: 1, result: "conflict", fault: "op" },
			{ v: 2, result: "conflict" },
		])
			expect(resetRefusal.schema.safeParse(answer).success, JSON.stringify(answer)).toBe(false);
	});
});
