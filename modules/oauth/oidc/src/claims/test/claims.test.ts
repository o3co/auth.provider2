import { describe, expect, it } from "vitest";
import { claimsAsked, claimsOf, scopeOfClaim, tableClaims, tableScopes } from "../claims.ts";

const attributes = {
	name: "Alice",
	picture: "https://img.example/a.png",
	email: "alice@example.com",
	email_verified: true,
	groups: ["admins", 7, "ops"],
	phone_number: "+1",
	address: { street: "x" },
};

describe("the claim table", () => {
	it("releases each scope's claims, from users' attribute of that name and type", () => {
		expect(claimsOf(attributes, ["profile"])).toEqual({
			name: "Alice",
			picture: "https://img.example/a.png",
		});
		expect(claimsOf(attributes, ["email"])).toEqual({
			email: "alice@example.com",
			email_verified: true,
		});
		// From groups, the elements that are not strings are dropped.
		expect(claimsOf(attributes, ["groups"])).toEqual({ groups: ["admins", "ops"] });
	});

	it("releases nothing for openid alone, never sub, nor an attribute outside the table", () => {
		expect(claimsOf(attributes, ["openid"])).toEqual({});
		expect(claimsOf({ ...attributes, sub: "x" }, ["openid", "phone", "address"])).toEqual({});
	});

	it("leaves out a value of another type, and counts only whole scope words", () => {
		expect(claimsOf({ name: 5, email_verified: "yes", groups: "admins" }, tableScopes)).toEqual({});
		expect(claimsOf(attributes, ["profile\temail", "email "])).toEqual({});
	});

	it("tells each table claim's scope, and none for a claim outside it", () => {
		expect(tableClaims.map((claim) => [claim, scopeOfClaim(claim)])).toEqual([
			["name", "profile"],
			["picture", "profile"],
			["email", "email"],
			["email_verified", "email"],
			["groups", "groups"],
		]);
		expect(scopeOfClaim("phone_number")).toBeUndefined();
		expect(scopeOfClaim("constructor")).toBeUndefined();
	});
});

describe("claims asked by name, and their constraints", () => {
	const target = (names: string[], constraints: object[] = []) => ({
		names: names.map((name) => ({ name, scope: scopeOfClaim(name) ?? "" })),
		constraints: constraints as never,
	});

	it("releases the table claims asked by name beside the scope's", () => {
		expect(claimsOf(attributes, ["profile"], target(["email"]))).toEqual({
			name: "Alice",
			picture: "https://img.example/a.png",
			email: "alice@example.com",
		});
	});

	it("leaves out a released claim its constraint does not hold, type and all, and a list any constraint names", () => {
		const asked = target(
			["email"],
			[
				{ name: "email", value: "bob@example.com" },
				{ name: "name", values: ["Alice", "A."] },
				{ name: "email_verified", value: "true" },
				{ name: "groups", values: ["admins"] },
			],
		);
		expect(claimsOf(attributes, ["profile", "email", "groups"], asked)).toEqual({
			name: "Alice",
			picture: "https://img.example/a.png",
		});
	});
});

describe("a claims parameter", () => {
	it("reads the table claims each target names, with their constraints, passing over what it does not read", () => {
		const asked = claimsAsked({
			id_token: {
				name: { essential: true, purpose: "x" },
				acr: { values: ["gold"] },
				auth_time: null,
			},
			userinfo: { email: { values: ["a@example.com", true, 3] }, nickname: [1, 2], picture: null },
			other: 1,
		});
		expect(asked).toEqual({
			subs: [],
			acr: [{ essential: false, values: ["gold"] }],
			selection: {
				idToken: { names: [{ name: "name", scope: "profile" }], constraints: [] },
				userinfo: {
					names: [
						{ name: "email", scope: "email" },
						{ name: "picture", scope: "profile" },
					],
					constraints: [{ name: "email", values: ["a@example.com", true, 3] }],
				},
			},
		});
	});

	it("reads the sub values each member asks, and refuses a sub of no shape §5.5.1 gives", () => {
		expect(
			claimsAsked({ id_token: { sub: { values: ["a", "b"] } }, userinfo: { sub: null } }),
		).toMatchObject({
			subs: [["a", "b"]],
		});
		for (const sub of [7, { value: 7 }, { values: [] }, { value: "a", values: ["b"] }]) {
			expect(claimsAsked({ id_token: { sub } }), JSON.stringify(sub)).toBe("malformed");
		}
	});

	it("reads the acr each member asks, kept apart, and refuses an acr of no shape §5.5.1 gives", () => {
		expect(
			claimsAsked({
				id_token: { acr: { essential: true, values: ["urn:a", "urn:b"] } },
				userinfo: { acr: null },
			}),
		).toMatchObject({
			acr: [
				{ essential: true, values: ["urn:a", "urn:b"] },
				{ essential: false, values: [] },
			],
		});
		for (const acr of [7, { value: 7 }, { values: [] }, { essential: "yes" }])
			expect(claimsAsked({ id_token: { acr } }), JSON.stringify(acr)).toBe("malformed");
	});

	it("refuses a parameter or a member that is no object, and a table claim of no shape or past the selection's bounds", () => {
		for (const value of ["{}", [], null, 3]) expect(claimsAsked(value)).toBe("malformed");
		for (const member of [123, [], "x", null])
			expect(claimsAsked({ id_token: member }), JSON.stringify(member)).toBe("malformed");
		expect(claimsAsked({ userinfo: [] })).toBe("malformed");
		const long = "x".repeat(257);
		for (const asked of [
			{ name: 5 },
			{ name: { value: ["a"] } },
			{ name: { value: { a: 1 } } },
			{ name: { value: null } },
			{ name: { value: Number.NaN } },
			{ name: { values: [] } },
			{ name: { value: "a", values: ["b"] } },
			{ name: { values: Array.from({ length: 17 }, (_, i) => `v${i}`) } },
			{ name: { value: long } },
			{ name: { essential: "yes" } },
		]) {
			expect(claimsAsked({ userinfo: asked }), JSON.stringify(asked)).toBe("malformed");
		}
		const wide = { values: Array.from({ length: 16 }, () => "y".repeat(100)) };
		expect(claimsAsked({ userinfo: { name: wide, email: wide }, id_token: { name: wide } })).toBe(
			"malformed",
		);
	});
});
