import { describe, expect, it } from "vitest";
import { credentialsOf, keyGenerationOf } from "../src/contract.ts";

const key = (credential: unknown) => ({ credential, publicKey: "pk", chain: [], position: 1 });

describe("credentialsOf", () => {
	it("reads each live key's credential id once, the state's other parts left unread", () => {
		const state = {
			keyGeneration: 1,
			keys: { r1: key("AQID"), r2: key("BAUG"), r3: key("AQID") },
			approvals: { a1: { anything: true } },
			whatever: [1, 2],
		};
		expect(credentialsOf(state)).toEqual(["AQID", "BAUG"]);
		expect(Object.isFrozen(credentialsOf(state))).toBe(true);
	});

	it("tells a state of no key from one that does not read", () => {
		expect(credentialsOf({ keys: {} })).toEqual([]);
		for (const state of [
			undefined,
			null,
			[],
			"keys",
			{},
			{ keys: [] },
			{ keys: null },
			{ keys: { r1: key("") } },
			{ keys: { r1: key(7) } },
			{ keys: { r1: "AQID" } },
			{ keys: { r1: {} } },
		])
			expect(credentialsOf(state), JSON.stringify(state)).toBeUndefined();
	});

	it("reads an entry by its own key, one the log named __proto__ too, and none it inherits", () => {
		const state: unknown = JSON.parse('{"keys":{"__proto__":{"credential":"AQID"}}}');
		expect(credentialsOf(state)).toEqual(["AQID"]);
		const inherited = Object.create({ keys: { r1: key("AQID") } });
		expect(credentialsOf(inherited)).toBeUndefined();
		// Keys inheriting an entry are no plain object, so none; a credential an entry inherits is none.
		expect(credentialsOf({ keys: Object.create({ r1: key("AQID") }) })).toBeUndefined();
		expect(credentialsOf({ keys: { r1: Object.create({ credential: "AQID" }) } })).toBeUndefined();
	});

	it("reads a credential id in its one spelling alone, and plain objects alone", () => {
		expect(credentialsOf({ keys: { r1: key("AQI") } })).toEqual(["AQI"]);
		for (const id of ["AQID=", "AQJ", "A", "AQ+/", "AQ I"])
			expect(credentialsOf({ keys: { r1: key(id) } }), id).toBeUndefined();
		for (const keys of [new Map(), new Date(0)])
			expect(credentialsOf({ keys }), String(keys)).toBeUndefined();
		expect(
			credentialsOf({ keys: Object.assign(Object.create(null), { r1: key("AQID") }) }),
		).toEqual(["AQID"]);
	});

	it("reads none where one entry does not read, among entries that do", () => {
		expect(credentialsOf({ keys: { r1: key("AQID"), r2: {}, r3: key("BAUG") } })).toBeUndefined();
		expect(credentialsOf({ keys: { r1: key("AQID"), r2: [] } })).toBeUndefined();
	});
});

describe("keyGenerationOf", () => {
	it("reads the key generation, a whole number from 0, or none", () => {
		expect(keyGenerationOf({ keyGeneration: 0, keys: {} })).toBe(0);
		expect(keyGenerationOf({ keyGeneration: 3 })).toBe(3);
		for (const state of [
			{},
			null,
			{ keyGeneration: -1 },
			{ keyGeneration: 1.5 },
			{ keyGeneration: "1" },
		])
			expect(keyGenerationOf(state), JSON.stringify(state)).toBeUndefined();
		expect(keyGenerationOf(Object.create({ keyGeneration: 1 }))).toBeUndefined();
		expect(Object.is(keyGenerationOf(JSON.parse('{"keyGeneration":-0}')), 0)).toBe(true);
	});
});
