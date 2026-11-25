import { readFileSync } from "node:fs";
import { passkeyThumbprintInput } from "@mod/passkey-key-wire";
import { keyThumbprintInput, payloads } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";

const vectorsOf = (wire: string) =>
	readFileSync(new URL("../test/keys.vectors.json", import.meta.resolve(wire)), "utf8");
const vectors = JSON.parse(vectorsOf("@mod/passkey-key-wire")) as {
	readonly accepted: readonly { readonly alg: number; readonly jwk: unknown }[];
	readonly jwkRefusals: readonly { readonly jwk: unknown }[];
};

// While sdk-core-wire's key form and passkey-key-wire both stand, their vectors are the same file and
// their thumbprint inputs the same bytes; taken out with sdk-core-wire's.
describe("sdk-core-wire's key form and passkey-key-wire, while both stand", () => {
	it("hold the same vectors, byte for byte", () => {
		expect(vectorsOf("@mod/passkey-key-wire")).toBe(vectorsOf("@mod/sdk-core-wire"));
	});

	it("give the same thumbprint input for each key, and none for the same refused ones", () => {
		for (const { jwk } of [...vectors.accepted, ...vectors.jwkRefusals])
			expect(passkeyThumbprintInput(jwk)).toBe(keyThumbprintInput(jwk));
		for (const value of [undefined, null, "key", 1, [], {}])
			expect(passkeyThumbprintInput(value)).toBe(keyThumbprintInput(value));
	});
});

// The algorithms a creation may offer are sdk-core-wire's; the key forms passkey-key-wire's. Each
// algorithm has one key form, and each key form an algorithm: the two lists name the same keys.
describe("the algorithms a creation offers and the key forms", () => {
	it("pair each algorithm with one key form, both ways", () => {
		// Every algorithm the schema takes, read from its literals: one added there shows here.
		const offered = payloads.creation.shape.creation.shape.options.shape.algorithms.element;
		const taken = offered.options.map((literal) => literal.value).sort((a, b) => a - b);
		const withKeys = [...new Set(vectors.accepted.map((v) => v.alg))].sort((a, b) => a - b);
		expect(taken).toEqual(withKeys);
		for (const alg of taken) expect(offered.safeParse(alg).success, String(alg)).toBe(true);
		for (const v of vectors.accepted)
			expect(passkeyThumbprintInput(v.jwk), String(v.alg)).toBeDefined();
	});
});
