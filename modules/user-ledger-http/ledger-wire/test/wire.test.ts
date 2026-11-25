import { describe, expect, it } from "vitest";
import { ledgerRoutes, usersWire, witnessWire } from "../src/contract.ts";

describe("the user ledger's calls", () => {
	it("puts the identifier under the name the ledger reads, and a lookup's keys as asked", () => {
		expect(usersWire.verify("alice", "pw")).toEqual({ email: "alice", password: "pw" });
		expect(usersWire.bySubject("u-1")).toEqual({ subject: "u-1" });
		expect(usersWire.byIdentifier("alice")).toEqual({ email: "alice" });
	});

	it("asks the ledger to create a subject for an identifier, answered 201, or 409 naming it taken", () => {
		expect(usersWire.create("alice")).toEqual({ email: "alice" });
		expect(usersWire.created).toBe(201);
		expect(usersWire.taken).toEqual({ 409: "exists" });
	});

	it("asks the ledger for an identifierless subject under an idempotency key, a SHA-256 in base64url", () => {
		const key = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
		expect(usersWire.createIdentifierless(key)).toEqual({ key });
		expect(usersWire.identifierlessKey.safeParse(key).success).toBe(true);
		for (const bad of ["", "short", `${key}=`, `${key.slice(0, 42)}V`, key.replace("4", "+")])
			expect(usersWire.identifierlessKey.safeParse(bad).success, bad).toBe(false);
	});

	it("says no such user only by a 404 or a 410 naming it", () => {
		expect(usersWire.noUser).toEqual({ 404: "not_found", 410: "gone" });
	});

	it("keeps no word a caller of auth.provider2 does not speak", () => {
		expect(Object.keys(usersWire).sort()).toEqual(
			[
				"byIdentifier",
				"bySubject",
				"create",
				"createIdentifierless",
				"created",
				"noUser",
				"taken",
				"identifierlessKey",
				"verify",
			].sort(),
		);
	});
});

describe("a witness ledger's calls", () => {
	it("sends the subject, the token where it names one, and the deadline of each write", () => {
		expect(witnessWire.read("s")).toEqual({ subject: "s" });
		expect(witnessWire.enroll("s", "t", 9)).toEqual({ subject: "s", token: "t", deadline: 9 });
		expect(witnessWire.withdraw("s", "t", 9)).toEqual({ subject: "s", token: "t", deadline: 9 });
		expect(witnessWire.clear("s", 9)).toEqual({ subject: "s", deadline: 9 });
		expect(witnessWire.written).toBe(204);
	});

	it("reads whether a subject is marked, and where withdraw is offered, the mark's token", () => {
		expect(witnessWire.readAnswer.safeParse({ enrolled: true }).success).toBe(true);
		expect(witnessWire.readAnswer.safeParse({ enrolled: "yes" }).success).toBe(false);
		const mark = (x: unknown) => witnessWire.markAnswer.safeParse(x).success;
		expect([mark({ enrolled: true, token: "t" }), mark({ enrolled: false })]).toEqual([true, true]);
		expect([mark({ enrolled: true }), mark({ enrolled: true, token: "" })]).toEqual([false, false]);
		expect(witnessWire.enrollAnswer.safeParse({ owner: false }).success).toBe(true);
		expect(witnessWire.enrollAnswer.safeParse({}).success).toBe(false);
	});
});

it("serves each call at a route of its own, the same for a fake ledger and the examples", () => {
	const routes = Object.values(ledgerRoutes).flatMap((calls) => Object.values(calls));
	expect(new Set(routes).size).toBe(routes.length);
	expect(Object.keys(ledgerRoutes.users)).toEqual([
		"verify",
		"subject",
		"identifier",
		"create",
		"createIdentifierless",
	]);
	expect(Object.keys(ledgerRoutes.passkeyWitness)).toEqual(["read", "enroll", "withdraw"]);
	expect(Object.keys(ledgerRoutes)).toEqual(["users", "passkeyWitness"]);
});

it("holds every word frozen", () => {
	for (const words of [usersWire, usersWire.noUser, usersWire.taken, witnessWire, ledgerRoutes]) {
		expect(Object.isFrozen(words)).toBe(true);
	}
	for (const calls of Object.values(ledgerRoutes)) expect(Object.isFrozen(calls)).toBe(true);
});
