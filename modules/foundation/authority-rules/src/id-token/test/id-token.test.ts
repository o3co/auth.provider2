import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { cHash } from "../id-token.ts";

const digest = (code: string) => createHash("sha256").update(code).digest();

describe("an ID token's rules", () => {
	it("derives c_hash from a code's digest: the left half of its SHA-256 (OpenID Connect Core §3.3.2.11)", () => {
		const code = "SplxlOBeZQQYbYS6WxSbIA";
		const whole = digest(code);
		expect(cHash(whole.toString("base64url"))).toBe(whole.subarray(0, 16).toString("base64url"));
		expect(cHash(whole.toString("base64url"))).toHaveLength(22);
	});

	it("takes no digest of another form", () => {
		const whole = digest("c").toString("base64url");
		for (const other of [
			"",
			whole.slice(1),
			`${whole}A`,
			`${whole.slice(0, -1)}B`,
			whole.replace(/.$/, "="),
		])
			expect(() => cHash(other)).toThrow(TypeError);
	});
});
