import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { keyThumbprint } from "../src/contract.ts";

/** passkey-key-wire's shared vectors of the key form, which every reader of it runs. */
const vectors: {
	readonly accepted: readonly { name: string; alg: number; cose: string; jkt: string }[];
	readonly coseRefusals: readonly { why: string; cose: string }[];
} = JSON.parse(
	readFileSync(
		new URL("../test/keys.vectors.json", import.meta.resolve("@mod/passkey-key-wire")),
		"utf8",
	),
);
const b64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");

describe("a passkey's thumbprint, from its COSE_Key", () => {
	it.each(vectors.accepted)("reads $name's key to its thumbprint and algorithm", (v) => {
		expect(keyThumbprint(b64(v.cose))).toEqual({ jkt: v.jkt, alg: v.alg });
	});

	it.each(vectors.coseRefusals)("has none for $why", ({ cose }) => {
		expect(keyThumbprint(b64(cose))).toBeUndefined();
	});

	it("has none for a key in another spelling of its bytes, or no key at all", () => {
		const key = b64(vectors.accepted[0]?.cose ?? "");
		for (const value of [`${key}=`, Buffer.from(key, "base64url").toString("base64"), "", "!"])
			expect(keyThumbprint(value), value).toBeUndefined();
	});
});
