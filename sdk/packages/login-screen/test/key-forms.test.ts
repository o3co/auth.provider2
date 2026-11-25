import { readFileSync } from "node:fs";
import { passkeyThumbprintInput } from "@mod/passkey-key-wire";
import { payloads } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";

const vectors = JSON.parse(
	readFileSync(
		new URL("../test/keys.vectors.json", import.meta.resolve("@mod/passkey-key-wire")),
		"utf8",
	),
) as { readonly accepted: readonly { readonly alg: number; readonly jwk: unknown }[] };

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
