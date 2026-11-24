/** A code's digest as a record names it: its SHA-256, 32 bytes in unpadded base64url. */
const sha256Digest = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * An ID token's `c_hash` (OpenID Connect Core §3.3.2.11) from its code's digest: the left half of
 * the code's SHA-256, base64url, as an ID token signed by an algorithm of SHA-256 carries it. The
 * monitor derives it from the digest a record names, as the Core does. A digest of another form is
 * the caller's error, a TypeError.
 */
export function cHash(codeDigest: string): string {
	if (!sha256Digest.test(codeDigest))
		throw new TypeError("authority-rules: not a code's SHA-256 digest");
	return Buffer.from(codeDigest, "base64url").subarray(0, 16).toString("base64url");
}
