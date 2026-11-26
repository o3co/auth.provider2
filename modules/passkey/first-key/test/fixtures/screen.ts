import { generateKeyPairSync } from "node:crypto";

/** A point of P-256 as the screen sends one: `eEnc` uncompressed, E_sig by its coordinates. */
export function screenPoints() {
	const point = () => {
		const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
			format: "jwk",
		});
		return {
			x: new Uint8Array(Buffer.from(jwk.x as string, "base64url")),
			y: new Uint8Array(Buffer.from(jwk.y as string, "base64url")),
		};
	};
	const enc = point();
	const sig = point();
	return {
		eEnc: new Uint8Array([0x04, ...enc.x, ...enc.y]),
		eSigX: sig.x,
		eSigY: sig.y,
	};
}
