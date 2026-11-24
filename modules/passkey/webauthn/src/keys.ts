import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { keyThumbprintInput } from "@mod/sdk-core-wire";

/** A passkey's key read from its COSE_Key: its algorithm as COSE numbers it, its thumbprint, the key. */
export interface PasskeyKey {
	readonly alg: number;
	readonly jkt: string;
	readonly key: KeyObject;
}

/** Where a byte string's bytes lie, its head in its shortest form at `at`; none for any other head. */
function bytesAt(
	cose: Buffer,
	at: number,
): { readonly start: number; readonly end: number } | undefined {
	const head = cose[at];
	if (head === undefined) return undefined;
	const [start, length] =
		head >= 0x40 && head < 0x58
			? [at + 1, head - 0x40]
			: head === 0x58
				? [at + 2, cose[at + 1] ?? 0]
				: head === 0x59 && at + 3 <= cose.length
					? [at + 3, cose.readUInt16BE(at + 1)]
					: [at, -1];
	// A length past its head's least form: a one-byte one under 24, a two-byte one under 256.
	const shortest = head < 0x58 || (head === 0x58 ? length >= 24 : length >= 256);
	return length >= 0 && shortest && start + length <= cose.length
		? { start, end: start + length }
		: undefined;
}

/**
 * A COSE_Key at `at` read to its JWK in the one form each key type has: CTAP2's canonical CBOR, its
 * key type's labels alone, in order, each once, of definite lengths. Where it ends; none otherwise.
 */
function coseKeyAt(
	cose: Buffer,
	at: number,
):
	| { readonly alg: number; readonly jwk: Readonly<Record<string, string>>; readonly end: number }
	| undefined {
	const opens = (hex: string) => cose.subarray(at, at + hex.length / 2).toString("hex") === hex;
	const text = (span: { start: number; end: number }) =>
		cose.subarray(span.start, span.end).toString("base64url");
	const x = bytesAt(cose, at + 8);
	if (!x) return undefined;
	if (opens("a401010327200621"))
		return { alg: -8, jwk: { crv: "Ed25519", kty: "OKP", x: text(x) }, end: x.end };
	// The label after the first byte string: -2 (0x21) for RSA's exponent, -3 (0x22) for EC2's y.
	const next = cose[x.end];
	const y = bytesAt(cose, x.end + 1);
	if (!y) return undefined;
	if (opens("a501020326200121") && next === 0x22)
		return { alg: -7, jwk: { crv: "P-256", kty: "EC", x: text(x), y: text(y) }, end: y.end };
	if (opens("a401030339010020") && next === 0x21)
		return { alg: -257, jwk: { e: text(y), kty: "RSA", n: text(x) }, end: y.end };
	return undefined;
}

/**
 * A passkey's key from its COSE_Key bytes in their one unpadded base64url spelling, read whole: one
 * of the protocol's algorithms, whatever a relying party offers; none for any other value.
 */
export function passkeyKey(publicKey: string): PasskeyKey | undefined {
	if (!/^[A-Za-z0-9_-]+$/.test(publicKey)) return undefined;
	const cose = Buffer.from(publicKey, "base64url");
	if (cose.toString("base64url") !== publicKey) return undefined;
	const read = coseKeyAt(cose, 0);
	const input = read && read.end === cose.length ? keyThumbprintInput(read.jwk) : undefined;
	if (!read || input === undefined) return undefined;
	try {
		// Node refuses a P-256 point off its curve.
		const key = createPublicKey({ key: read.jwk, format: "jwk" });
		return { alg: read.alg, jkt: createHash("sha256").update(input).digest("base64url"), key };
	} catch {
		return undefined;
	}
}

/** A passkey's thumbprint (sdk-core-wire's `keyThumbprintInput`, hashed) and algorithm, from its COSE_Key; none for any other value. */
export function keyThumbprint(
	publicKey: string,
): { readonly jkt: string; readonly alg: number } | undefined {
	const read = passkeyKey(publicKey);
	return read && { jkt: read.jkt, alg: read.alg };
}

/**
 * The key an assertion is verified by, and the hash its signature is over (none for EdDSA): a
 * passkey's COSE_Key, or, where the first byte is 0x04, an uncompressed P-256 point. Throws for any
 * other value.
 */
export function assertionKey(publicKey: string): {
	readonly key: KeyObject;
	readonly hash: "sha256" | null;
} {
	if (!/^[A-Za-z0-9_-]+$/.test(publicKey)) throw new TypeError("no key");
	const bytes = Buffer.from(publicKey, "base64url");
	if (bytes[0] === 4) {
		if (bytes.length !== 65) throw new TypeError("no uncompressed point");
		const x = bytes.subarray(1, 33).toString("base64url");
		const y = bytes.subarray(33).toString("base64url");
		return {
			key: createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" }),
			hash: "sha256",
		};
	}
	const read = passkeyKey(publicKey);
	if (!read) throw new TypeError("no passkey's key");
	return { key: read.key, hash: read.alg === -8 ? null : "sha256" };
}
