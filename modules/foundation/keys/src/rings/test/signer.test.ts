import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { isUnavailable, type Log } from "@mod/kernel";
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

describe("a signature its holder answers", () => {
	const answering = (signature: Uint8Array) => {
		const errors: unknown[] = [];
		const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
		const signing = { kid: "k", alg: "ES256", key } as const;
		const holding = {
			sign: async () => ({ kind: "signed", signature }) as const,
		} as unknown as KeyHolder;
		const logged = {
			error: (event: string, fields: object) => errors.push({ event, ...fields }),
		} as unknown as Log;
		const signer = ringSigner(
			"authority",
			{ signing, verifying: [signing] },
			holding,
			() => 0,
			logged,
		);
		return { signer, errors };
	};
	const payload = new TextEncoder().encode('{"a":1}');

	it("is taken at the length its prepared said, and at any other is a holder's fault, never an outage", async () => {
		const right = answering(new Uint8Array(64));
		const prepared = right.signer.prepare("JWT");
		expect(await right.signer.sign(prepared, payload)).toMatchObject({ kind: "signed" });
		// An ECDSA signature in DER (70 bytes or so), or P1363 short of a leading zero, where 64 is said.
		for (const length of [71, 63]) {
			const wrong = answering(new Uint8Array(length));
			const failed = wrong.signer.sign(wrong.signer.prepare("JWT"), payload);
			await expect(failed).rejects.toThrow(/another length/);
			await expect(failed).rejects.not.toSatisfy(isUnavailable);
			const fields = { use: "authority", kid: "k", said: "64", answered: String(length) };
			expect(wrong.errors).toEqual([{ event: "keys.signature_length", ...fields }]);
		}
	});
});
