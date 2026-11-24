import type { SigningKey } from "@mod/sdk-core-wire";
import { base64url } from "./bytes.ts";

/** The screen's two keys for one ceremony: E_enc (HPKE's P-256 point) and E_sig (a P-256 signing key). */
export interface ScreenKeys {
	/** E_enc's public point, HPKE's raw P-256 form, base64url: a statement's `e_enc`. */
	readonly eEnc: string;
	/** E_sig's public key as a statement carries it: P-256's x and y alone. */
	readonly eSig: SigningKey;
	readonly encryption: CryptoKeyPair;
	readonly signing: CryptoKeyPair;
}

/** A fresh pair of screen keys; the private halves cannot be exported. */
export async function screenKeys(): Promise<ScreenKeys> {
	const encryption = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
		"deriveBits",
	]);
	const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
		"sign",
		"verify",
	]);
	const point = new Uint8Array(await crypto.subtle.exportKey("raw", encryption.publicKey));
	const jwk = await crypto.subtle.exportKey("jwk", signing.publicKey);
	return {
		eEnc: base64url(point),
		eSig: { kty: "EC", crv: "P-256", x: jwk.x ?? "", y: jwk.y ?? "" },
		encryption,
		signing,
	};
}

/** Whether a statement's keys are these screen keys. */
export const namesKeys = (keys: ScreenKeys, eEnc: string, eSig: SigningKey) =>
	eEnc === keys.eEnc && eSig.x === keys.eSig.x && eSig.y === keys.eSig.y;
