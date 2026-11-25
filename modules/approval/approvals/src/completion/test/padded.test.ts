import { hpke } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { paddedFor } from "../padded.ts";

const jws = "aGVhZA.cGF5bG9hZA.c2ln";
const id = (bytes: number) => Buffer.alloc(bytes, 7).toString("base64url");

it("pads to the bucket the longest credential ID's bytes choose, never its count or text length", () => {
	const [small, large] = hpke.completionBuckets;
	expect(paddedFor(jws, [])).toHaveLength(small);
	// 128 bytes is 171 characters: the bytes count, not the characters.
	expect(paddedFor(jws, [id(128), id(1), id(128)])).toHaveLength(small);
	expect(paddedFor(jws, [id(1), id(129)])).toHaveLength(large);
	expect(hpke.unpaddedCompletion(paddedFor(jws, [id(129)]) as string)).toBe(jws);
});

it("gives none for a completion its bucket does not hold, so it is never sealed", () => {
	expect(paddedFor(`${jws}${"A".repeat(hpke.completionBuckets[0])}`, [id(16)])).toBeUndefined();
});
