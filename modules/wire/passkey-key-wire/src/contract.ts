import { z } from "zod";

/**
 * A passkey's public key as both sides read it: its JWK, its thumbprint's members alone, and what its
 * thumbprint (RFC 7638; RFC 8037 for an OKP key) is the SHA-256 of. Which algorithms a ceremony may
 * offer, and the thumbprint's value in a statement, are sdk-core-wire's.
 */

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** 32 bytes in their one unpadded base64url spelling: 43 characters, the last carrying no bit past them. */
const bytes32 = z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
const sextet = (text: string, at: number) => alphabet.indexOf(text.charAt(at));

/**
 * An RSA modulus in its one unpadded base64url spelling, its first byte not 0 (one that is is
 * refused, never cut), of 2048 to 4096 bits, and odd.
 */
function isModulus(text: string): boolean {
	const rest = text.length % 4;
	if (!/^[A-Za-z0-9_-]+$/.test(text) || rest === 1) return false;
	// The last character's bits past the bytes (4 where a group ends in 2 characters, 2 in 3) are 0,
	// and the last byte's lowest bit, the one above them, is 1: a modulus is odd.
	const unit = rest === 2 ? 16 : rest === 3 ? 4 : 1;
	const last = sextet(text, text.length - 1);
	if (last % unit !== 0 || (last / unit) % 2 !== 1) return false;
	const bytes = ((text.length - rest) / 4) * 3 + (rest === 0 ? 0 : rest - 1);
	const high = sextet(text, 0) * 4 + (sextet(text, 1) - (sextet(text, 1) % 16)) / 16;
	// 2048 bits are 256 bytes, the first of them 128 or more; 4096 bits are 512 bytes.
	return high !== 0 && (bytes === 256 ? high >= 128 : bytes > 256 && bytes <= 512);
}

/** A passkey's public key as a JWK, its thumbprint's members alone, for each key type a passkey may be of. */
const publicJwk = z.discriminatedUnion("kty", [
	z.object({ crv: z.literal("P-256"), kty: z.literal("EC"), x: bytes32, y: bytes32 }).strict(),
	z.object({ crv: z.literal("Ed25519"), kty: z.literal("OKP"), x: bytes32 }).strict(),
	z
		.object({ e: z.literal("AQAB"), kty: z.literal("RSA"), n: z.string().refine(isModulus) })
		.strict(),
]);
export type PasskeyPublicJwk = z.infer<typeof publicJwk>;

/**
 * What a passkey's thumbprint is the SHA-256 of: the JWK's required members in RFC 7638's order
 * (sorted), with no space. A JWK that is not a passkey's as `PasskeyPublicJwk` holds it (another
 * member, another spelling of the same bytes, a value out of its bounds) has none.
 */
export function passkeyThumbprintInput(jwk: unknown): string | undefined {
	const read = publicJwk.safeParse(jwk);
	if (!read.success) return undefined;
	const key = read.data;
	const members: readonly (readonly [string, string])[] =
		key.kty === "EC"
			? [
					["crv", key.crv],
					["kty", key.kty],
					["x", key.x],
					["y", key.y],
				]
			: key.kty === "OKP"
				? [
						["crv", key.crv],
						["kty", key.kty],
						["x", key.x],
					]
				: [
						["e", key.e],
						["kty", key.kty],
						["n", key.n],
					];
	return `{${members.map(([name, value]) => `${JSON.stringify(name)}:${JSON.stringify(value)}`).join(",")}}`;
}
