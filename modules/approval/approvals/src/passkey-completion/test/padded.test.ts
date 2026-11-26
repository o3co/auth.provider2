import { rsaModulusCeiling } from "@mod/keys/testing";
import { hpke } from "@mod/sdk-core-wire";
import { expect, it } from "vitest";
import { world } from "../../../test/fixtures/world.ts";
import { beyondLimits, paddedFor } from "../padded.ts";

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

it("tells why an issuer or a Core key passes the wire's limits, and nothing where they fit", () => {
	const { issuerChars, kidChars, rsaBits } = hpke.completionLimits;
	const ec = { kty: "EC", kid: "k".repeat(kidChars), x: "x", y: "y" };
	const rsa = (bits: number) => ({
		kty: "RSA",
		kid: "r",
		// A modulus of exactly `bits` bits: its highest bit set.
		n: Buffer.alloc(bits / 8, 0xff).toString("base64url"),
	});
	const fit = `https://${"a".repeat(issuerChars - 8)}`;
	expect(beyondLimits(fit, [ec, rsa(rsaBits)])).toBeUndefined();
	expect(beyondLimits(`${fit}a`, [])).toMatch(/issuer/);
	expect(beyondLimits(fit, [{ ...ec, kid: "k".repeat(kidChars + 1) }])).toMatch(/kid/);
	expect(beyondLimits(fit, [rsa(rsaBits + 8)])).toMatch(/RSA/);
	// Each key held, whichever comes first.
	expect(beyondLimits(fit, [ec, rsa(rsaBits + 8)])).toMatch(/key r .*RSA/);
	expect(beyondLimits(`${fit}a`, [])).toMatch(/^issuer\.url/);
});

it("refuses boot for an issuer past the wire's limit, and boots at it", async () => {
	const { issuerChars } = hpke.completionLimits;
	const at = `https://${"a".repeat(issuerChars - 8)}`;
	await expect(world({ issuer: at })).resolves.toBeDefined();
	await expect(world({ issuer: `${at}a` })).rejects.toMatchObject({
		refusals: [expect.objectContaining({ reason: expect.stringMatching(/issuer/) })],
	});
});

it("bounds a Core key's RSA as keys does: the completion's limit is keys' own ceiling", () => {
	// Each word has its owner (sdk-core-wire's limit, keys' ceiling); a key keys takes fits the completion.
	expect(hpke.completionLimits.rsaBits).toBe(rsaModulusCeiling);
});
