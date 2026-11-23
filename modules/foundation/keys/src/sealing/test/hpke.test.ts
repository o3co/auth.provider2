import { createECDH } from "node:crypto";
import { describe, expect, it } from "vitest";
import { derivedKeyPair, openWith, sealTo } from "../hpke.ts";

const hex = (text: string) => new Uint8Array(Buffer.from(text.replace(/\s+/g, ""), "hex"));

/** RFC 9180, A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, sequence 0. */
const vector = {
	info: hex("4f6465206f6e2061204772656369616e2055726e"),
	ikmE: hex("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"),
	pkEm: hex(`04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32
		5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4`),
	skEm: hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"),
	ikmR: hex("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"),
	pkRm: hex(`04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
		6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0`),
	skRm: hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"),
	pt: hex("4265617574792069732074727574682c20747275746820626561757479"),
	aad: hex("436f756e742d30"),
	ct: hex(`5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f
		9076ac232e3ab2523f39513434`),
};

/** The recipient's Diffie-Hellman, as a holder of skR answers it. */
const agreeing = (skR: Uint8Array) => async (pkE: Uint8Array) => {
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(skR);
	return new Uint8Array(ecdh.computeSecret(pkE));
};

describe("HPKE, as RFC 9180 gives it for the suite sdk-core-wire names", () => {
	it("derives a key pair from its input keying material", () => {
		const derived = derivedKeyPair(vector.ikmE);
		expect(Buffer.from(derived.secret).toString("hex")).toBe(
			Buffer.from(vector.skEm).toString("hex"),
		);
		expect(Buffer.from(derived.point).toString("hex")).toBe(
			Buffer.from(vector.pkEm).toString("hex"),
		);
		expect(Buffer.from(derivedKeyPair(vector.ikmR).point)).toEqual(Buffer.from(vector.pkRm));
	});

	it("seals the test vector's plaintext to its ciphertext, and opens it back", async () => {
		const sealed = sealTo(vector.pkRm, vector.info, vector.aad, vector.pt, vector.ikmE);
		expect(Buffer.from(sealed.enc)).toEqual(Buffer.from(vector.pkEm));
		expect(Buffer.from(sealed.ct)).toEqual(Buffer.from(vector.ct));
		const opened = await openWith(
			agreeing(vector.skRm),
			vector.pkRm,
			sealed,
			vector.info,
			vector.aad,
		);
		expect(opened && Buffer.from(opened)).toEqual(Buffer.from(vector.pt));
	});

	it("opens nothing where the additional data, the info, the encapsulated key or the ciphertext differ", async () => {
		const open = agreeing(vector.skRm);
		const flipped = (bytes: Uint8Array, at: number) => {
			const copy = new Uint8Array(bytes);
			copy[at] = (copy[at] ?? 0) ^ 1;
			return copy;
		};
		const sealed = { enc: vector.pkEm, ct: vector.ct };
		const other = new TextEncoder().encode("other");
		expect(await openWith(open, vector.pkRm, sealed, vector.info, other)).toBeUndefined();
		expect(await openWith(open, vector.pkRm, sealed, other, vector.aad)).toBeUndefined();
		expect(
			await openWith(
				open,
				vector.pkRm,
				{ ...sealed, ct: flipped(vector.ct, 3) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
		expect(
			await openWith(
				open,
				vector.pkRm,
				{ ...sealed, enc: flipped(vector.pkEm, 10) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
		expect(
			await openWith(
				open,
				vector.pkRm,
				{ ...sealed, enc: vector.pkEm.subarray(1) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
	});

	it("refuses to seal to what is no P-256 point", () => {
		expect(() =>
			sealTo(new Uint8Array(65), vector.info, vector.aad, vector.pt, vector.ikmE),
		).toThrow(TypeError);
	});
});
