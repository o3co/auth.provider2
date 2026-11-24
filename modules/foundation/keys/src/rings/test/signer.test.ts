import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { Log } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { KeyHolder } from "../../contract.ts";
import { ringSigner } from "../signer.ts";

const holder = {} as KeyHolder;
const log = {} as Log;
const signerOver = (key: KeyObject) => {
	const signing = { kid: "k", alg: "ES256", key } as const;
	return ringSigner("authority", { signing, verifying: [signing] }, holder, () => 0, log);
};

describe("a prepared signature's length", () => {
	it("is refused for a key whose signature length it does not know, never taken as none", () => {
		for (const key of [
			generateKeyPairSync("x25519").publicKey,
			generateKeyPairSync("ec", { namedCurve: "secp256k1" }).publicKey,
		]) {
			expect(() => signerOver(key).prepare("JWT")).toThrow(TypeError);
		}
	});

	it("counts an Ed448 key's as RFC 8032 writes it", () => {
		expect(signerOver(generateKeyPairSync("ed448").publicKey).prepare("JWT").signatureLength).toBe(
			114,
		);
	});
});
