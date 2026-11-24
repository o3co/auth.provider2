import { hpke } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { openSealed, sealTo, sealToWith } from "../src/hpke.ts";
import { pointKeyPair } from "./fixtures.ts";

const hex = (text: string) => new Uint8Array(Buffer.from(text.replace(/\s+/g, ""), "hex"));

/** RFC 9180, A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, sequence 0. */
const vector = {
	info: hex("4f6465206f6e2061204772656369616e2055726e"),
	pkEm: hex(`04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32
		5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4`),
	skEm: hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"),
	pkRm: hex(`04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
		6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0`),
	skRm: hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"),
	pt: hex("4265617574792069732074727574682c20747275746820626561757479"),
	aad: hex("436f756e742d30"),
	ct: hex(`5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f
		9076ac232e3ab2523f39513434`),
};

describe("HPKE, as RFC 9180 gives it for the suite sdk-core-wire names", () => {
	it("names the suite it implements", () => {
		expect(hpke).toMatchObject({
			kem: "DHKEM(P-256, HKDF-SHA256)",
			kdf: "HKDF-SHA256",
			aead: "AES-128-GCM",
		});
	});

	it("seals the test vector's plaintext to its ciphertext with its ephemeral key", async () => {
		const ephemeral = await pointKeyPair(vector.skEm, vector.pkEm, "ECDH");
		const sealed = await sealToWith(ephemeral, vector.pkRm, vector.info, vector.aad, vector.pt);
		expect(Buffer.from(sealed.enc)).toEqual(Buffer.from(vector.pkEm));
		expect(Buffer.from(sealed.ct)).toEqual(Buffer.from(vector.ct));
	});

	it("opens the test vector's ciphertext with the recipient's key", async () => {
		const recipient = await pointKeyPair(vector.skRm, vector.pkRm, "ECDH");
		const opened = await openSealed(
			recipient,
			{ enc: vector.pkEm, ct: vector.ct },
			vector.info,
			vector.aad,
		);
		expect(opened && Buffer.from(opened)).toEqual(Buffer.from(vector.pt));
	});

	it("seals with a fresh ephemeral key each time, and opens what it sealed", async () => {
		const recipient = await pointKeyPair(vector.skRm, vector.pkRm, "ECDH");
		const a = await sealTo(vector.pkRm, vector.info, vector.aad, vector.pt);
		const b = await sealTo(vector.pkRm, vector.info, vector.aad, vector.pt);
		expect(Buffer.from(a.enc)).not.toEqual(Buffer.from(b.enc));
		const opened = await openSealed(recipient, a, vector.info, vector.aad);
		expect(opened && Buffer.from(opened)).toEqual(Buffer.from(vector.pt));
	});

	it("opens nothing where the additional data, the info, the encapsulated key or the ciphertext differ", async () => {
		const recipient = await pointKeyPair(vector.skRm, vector.pkRm, "ECDH");
		const flipped = (bytes: Uint8Array, at: number) => {
			const copy = new Uint8Array(bytes);
			copy[at] = (copy[at] ?? 0) ^ 1;
			return copy;
		};
		const sealed = { enc: vector.pkEm, ct: vector.ct };
		const other = new TextEncoder().encode("other");
		expect(await openSealed(recipient, sealed, vector.info, other)).toBeUndefined();
		expect(await openSealed(recipient, sealed, other, vector.aad)).toBeUndefined();
		expect(
			await openSealed(
				recipient,
				{ ...sealed, ct: flipped(vector.ct, 3) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
		expect(
			await openSealed(
				recipient,
				{ ...sealed, enc: flipped(vector.pkEm, 5) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
		expect(
			await openSealed(
				recipient,
				{ ...sealed, ct: vector.ct.subarray(0, 8) },
				vector.info,
				vector.aad,
			),
		).toBeUndefined();
	});

	it("refuses to seal to a point that is not on P-256", async () => {
		const off = new Uint8Array(vector.pkRm);
		off[64] = (off[64] ?? 0) ^ 1;
		await expect(sealTo(off, vector.info, vector.aad, vector.pt)).rejects.toThrow();
	});
});
