import { hpke } from "@mod/sdk-core-wire";

/** A completion padded to the bucket its longest credential ID's bytes choose; none where it does not fit, never sealed. */
export const paddedFor = (jws: string, ids: readonly string[]): string | undefined =>
	hpke.paddedCompletion(jws, longestOf(ids));
export const longestOf = (ids: readonly string[]) =>
	Math.max(0, ...ids.map((id) => Buffer.from(id, "base64url").length));

/** Why this Core's issuer or a Core key passes sdk-core-wire's completion limits; none where they fit. */
export function beyondLimits(
	issuer: string,
	keys: readonly Readonly<Record<string, unknown>>[],
): string | undefined {
	const { issuerChars, kidChars, rsaBits } = hpke.completionLimits;
	const holds = "the most a passkey completion's bucket holds";
	if (issuer.length > issuerChars)
		return `issuer.url is longer than ${issuerChars} characters, ${holds}`;
	for (const key of keys) {
		const named = `keys.core: the key ${String(key.kid)} (generation ${String(key.generation)})`;
		if (typeof key.kid === "string" && key.kid.length > kidChars)
			return `${named} has a kid longer than ${kidChars} characters, ${holds}`;
		if (key.kty === "RSA" && typeof key.n === "string")
			if (Buffer.from(key.n, "base64url").length * 8 > rsaBits)
				return `${named} has an RSA modulus over ${rsaBits} bits, ${holds}`;
	}
	return undefined;
}
