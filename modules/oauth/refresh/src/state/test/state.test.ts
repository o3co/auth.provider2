import { emptyState } from "@mod/authority-rules";
import { describe, expect, it } from "vitest";
import { familiesOwner, familiesPart } from "../state.ts";

const family = {
	approval: "a1",
	client: "rp",
	rotation: 0,
	chain: ["k1", "a1"],
	position: 3,
	acceptedAt: 1,
};

describe("refresh's part of a subject's flow", () => {
	it("holds the state's families alone, in its own part", () => {
		expect(familiesOwner.holds).toEqual(["families"]);
		expect(familiesOwner.parts).toEqual([familiesPart]);
		expect(familiesOwner.records({ of: "subject", id: "s1" })).toEqual([
			{ part: familiesPart, name: "state" },
		]);
	});

	it("reads the families its record holds, none where it holds none", () => {
		expect(familiesOwner.read([undefined])).toEqual({ families: {} });
		expect(familiesOwner.read([{ families: { b1: family } }])).toEqual({
			families: { b1: family },
		});
	});

	it("writes the families only where they changed", () => {
		const state = { ...emptyState, families: { b1: family } };
		expect(familiesOwner.write(state, [undefined])).toEqual([
			{ value: { families: { b1: family } } },
		]);
		expect(familiesOwner.write(state, [{ families: { b1: family } }])).toEqual([undefined]);
		expect(familiesOwner.write(emptyState, [undefined])).toEqual([undefined]);
	});
});
