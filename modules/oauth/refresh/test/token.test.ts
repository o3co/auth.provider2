import { randomBytes } from "node:crypto";
import { requests } from "@mod/front-core-wire";
import { expect, it } from "vitest";
import { tokenOf, tokenParts } from "../src/record.ts";

const secret = randomBytes(32).toString("base64url");

it("makes a token the Front's wire carries in a refresh's `refreshToken`, up to a family id of 63 bytes", () => {
	const spec = requests.refresh.fields.find((f) => f.name === "refreshToken");
	expect(spec).toMatchObject({ type: "b64url" });
	for (const family of ["r1", "fam-0001", "f".repeat(63), "é".repeat(31)]) {
		const token = tokenOf(family, secret);
		expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(token.length).toBeGreaterThanOrEqual(spec?.min ?? Number.NaN);
		expect(token.length).toBeLessThanOrEqual(spec?.max ?? Number.NaN);
		expect(tokenParts(token)).toEqual({ family, secret });
	}
	// A family id the wire could not carry in a token: no token is made.
	expect(() => tokenOf("f".repeat(64), secret)).toThrow(TypeError);
	expect(() => tokenOf("r1", "s".repeat(42))).toThrow(TypeError);
	expect(() => tokenOf("r1", `${"A".repeat(42)}B`)).toThrow(TypeError);
	// A family id no token reads back as itself: none, or not text UTF-8 keeps.
	expect(() => tokenOf("", secret)).toThrow(TypeError);
	expect(() => tokenOf("a\ud800b", secret)).toThrow(TypeError);
});

it("reads a token only in the very form it made it", () => {
	const token = tokenOf("r-bundle", secret);
	const encoded = token.slice(43);
	for (const other of [
		"",
		secret,
		`${token}=`,
		`${token} `,
		`${token}!`,
		// The form with a dot between its family and its secret, which the Front's wire does not carry.
		`${encoded}.${secret}`,
		`${secret}.${encoded}`,
		// Another spelling of the same bytes: base64url's decoder would read it alike.
		`${secret}${encoded.slice(0, -1)}${String.fromCharCode(encoded.charCodeAt(encoded.length - 1) + 1)}`,
		`${token}${"A".repeat(128 - token.length + 1)}`,
		// A secret spelled with its last character's unused bits set: the same 32 bytes, another text.
		`${"A".repeat(42)}B${encoded}`,
	]) {
		expect(tokenParts(other), other).toBeUndefined();
	}
});
