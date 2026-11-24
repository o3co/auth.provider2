import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type LoginFacts, sessionRules } from "../../contract.ts";

const facts: LoginFacts = {
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: "opening",
	provenSince: 0,
	endsAt: 3_600_000,
};

describe("session's rules", () => {
	it("takes a proof's start of epoch milliseconds, and throws a TypeError for none or anything else", () => {
		expect(() => sessionRules.checkProvenSince(facts)).not.toThrow();
		expect(() => sessionRules.checkProvenSince({ ...facts, provenSince: 8.64e15 })).not.toThrow();
		for (const provenSince of [undefined, -1, 8.64e15 + 1, Number.NaN, "1", null]) {
			expect(
				() => sessionRules.checkProvenSince({ ...facts, provenSince } as never),
				String(provenSince),
			).toThrow(TypeError);
		}
	});

	it("takes an end of whole epoch milliseconds, and throws a TypeError, naming no value, for none or anything else", () => {
		expect(() => sessionRules.checkEndsAt(facts)).not.toThrow();
		expect(() => sessionRules.checkEndsAt({ ...facts, endsAt: 0 })).not.toThrow();
		for (const endsAt of [undefined, -1, 8.64e15 + 1, Number.NaN, "1", null, 1.5]) {
			const checked = () => sessionRules.checkEndsAt({ ...facts, endsAt } as never);
			expect(checked, String(endsAt)).toThrow(TypeError);
			expect(checked).not.toThrow(String(endsAt));
		}
	});

	it("takes an authentication time of epoch milliseconds, opening or unknown, and throws a TypeError for anything else", () => {
		for (const authenticatedAt of [0, 8.64e15, "opening", "unknown"] as const) {
			expect(() => sessionRules.checkAuthenticatedAt({ ...facts, authenticatedAt })).not.toThrow();
		}
		for (const authenticatedAt of [-1, Number.NaN, 8.64e15 + 1, "later", undefined]) {
			expect(
				() => sessionRules.checkAuthenticatedAt({ ...facts, authenticatedAt } as never),
				String(authenticatedAt),
			).toThrow(TypeError);
		}
	});

	it("keeps the authentication time a login reports, the opening for a later one or for opening, and the opening unknown", () => {
		const capped: number[] = [];
		const of = (authenticatedAt: LoginFacts["authenticatedAt"]) =>
			sessionRules.authenticatedAtOf({ ...facts, authenticatedAt }, 100, () => capped.push(1));
		expect(of(50)).toEqual({ authenticatedAt: 50 });
		expect(of("opening")).toEqual({ authenticatedAt: 100 });
		expect(of("unknown")).toEqual({ authenticatedAt: 100, authenticatedAtUnknown: true });
		expect(capped).toEqual([]);
		expect(of(150)).toEqual({ authenticatedAt: 100 });
		expect(capped).toEqual([1]);
	});

	it("closes each listed session in the listing's order, past one that fails or is left pending, and then fails", async () => {
		const members = async () => ["x", "y", "z"].map((member) => ({ member }));
		const closed: string[] = [];
		const close = async (handle: string) => {
			closed.push(handle);
			if (handle === "x") throw new Error("down");
			return { kind: handle === "y" ? ("pending" as const) : ("closed" as const) };
		};
		await expect(sessionRules.closeListed("alice", { members }, close)).rejects.toSatisfy(
			isUnavailable,
		);
		expect(closed).toEqual(["x", "y", "z"]);
		const done = async () => ({ kind: "closed" as const });
		await expect(sessionRules.closeListed("alice", { members }, done)).resolves.toBeUndefined();
	});
});
