import { base64url, fromBase64url, textOf, utf8 } from "./bytes.ts";

/** The algorithms a Core ring signs with, each by WebCrypto's parameters and the key kind it fits. */
const algorithms = {
	ES256: {
		import: { name: "ECDSA", namedCurve: "P-256" },
		verify: { name: "ECDSA", hash: "SHA-256" },
		fits: (jwk: JsonWebKey) => jwk.kty === "EC" && jwk.crv === "P-256",
	},
	EdDSA: {
		import: { name: "Ed25519" },
		verify: { name: "Ed25519" },
		fits: (jwk: JsonWebKey) => jwk.kty === "OKP" && jwk.crv === "Ed25519",
	},
	RS256: {
		import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		verify: { name: "RSASSA-PKCS1-v1_5" },
		fits: (jwk: JsonWebKey) => jwk.kty === "RSA",
	},
	PS256: {
		import: { name: "RSA-PSS", hash: "SHA-256" },
		verify: { name: "RSA-PSS", saltLength: 32 },
		fits: (jwk: JsonWebKey) => jwk.kty === "RSA",
	},
} as const;
type Alg = keyof typeof algorithms;
const isAlg = (alg: unknown): alg is Alg =>
	typeof alg === "string" && Object.hasOwn(algorithms, alg);

/** A key's algorithm: its `alg`, or for a key with none, the one its curve fixes (no RSA key, which fits two). */
const algOf = (jwk: JsonWebKey): Alg | undefined => {
	if (jwk.alg !== undefined) return isAlg(jwk.alg) ? jwk.alg : undefined;
	if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
	if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
	return undefined;
};
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;
/** An unsigned big-endian integer's bit length, leading zero bytes left out. */
const bitLength = (bytes: Uint8Array) => {
	const first = bytes.findIndex((byte) => byte !== 0);
	return first < 0 ? 0 : (bytes.length - first - 1) * 8 + (32 - Math.clz32(bytes[first] ?? 0));
};
/** The least RSA modulus a key may have, in bits (RFC 7518 §3.3). */
const rsaBits = 2048;

/** Whether a key may verify a signature: no private member, `use` (if any) `sig`, `key_ops` (if any) holding `verify`, an RSA modulus long enough. */
const verifies = (jwk: Jwk) => {
	if (privateMembers.some((name) => name in jwk)) return false;
	if (keyIdentity(jwk) === undefined) return false;
	if (jwk.use !== undefined && jwk.use !== "sig") return false;
	if (jwk.key_ops !== undefined && !jwk.key_ops.includes("verify")) return false;
	if (jwk.kty !== "RSA") return true;
	const modulus = fromBase64url(jwk.n ?? "");
	return modulus !== undefined && bitLength(modulus) >= rsaBits;
};

const object = (text: string | undefined): Record<string, unknown> | undefined => {
	if (text === undefined) return undefined;
	try {
		const value: unknown = JSON.parse(text);
		return value !== null && typeof value === "object" && !Array.isArray(value)
			? (value as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
};
const decoded = (part: string) => {
	const bytes = fromBase64url(part);
	return bytes && textOf(bytes);
};

/** A public JWK, as a key set carries it: with its `kid` where it has one. */
export type Jwk = JsonWebKey & { readonly kid?: string };

/** A member's canonical base64url, an integer's with its leading zero bytes left out, or none where it is no canonical base64url. */
function member(text: string | undefined, integer = false): string | undefined {
	const bytes = text === undefined ? undefined : fromBase64url(text);
	if (!bytes) return undefined;
	const first = integer ? bytes.findIndex((byte) => byte !== 0) : 0;
	return base64url(first < 0 ? new Uint8Array() : bytes.subarray(first));
}

/**
 * A public key's identity: its kind's public members alone (EC: crv, x, y; OKP: crv, x; RSA: n, e),
 * each canonical, whatever else it carries. None for another kind, or a member not canonical.
 */
export function keyIdentity(jwk: Jwk): string | undefined {
	const parts =
		jwk.kty === "EC"
			? [jwk.crv, member(jwk.x), member(jwk.y)]
			: jwk.kty === "OKP"
				? [jwk.crv, member(jwk.x)]
				: jwk.kty === "RSA"
					? [member(jwk.n, true), member(jwk.e, true)]
					: [undefined];
	return parts.every((part) => typeof part === "string" && part !== "")
		? `${jwk.kty}:${parts.join(":")}`
		: undefined;
}

/** What a verified compact JWS reads as: its header and payload, each a JSON object. */
export interface Verified {
	readonly header: Readonly<Record<string, unknown>>;
	readonly payload: Readonly<Record<string, unknown>>;
}

/**
 * Verifies a compact JWS with one of the public keys: a key verifies under its own algorithm
 * alone, which the header must name, and only where the header's `kid` (if any) is the key's. A
 * header with `crit` or `b64` is refused, as is a key not for verifying signatures.
 * Answers its header and payload, or none.
 */
export async function verifyCompact(
	jws: string,
	keys: readonly Jwk[],
): Promise<Verified | undefined> {
	const parts = jws.split(".");
	if (parts.length !== 3) return undefined;
	const [h = "", p = "", s = ""] = parts;
	const header = object(decoded(h));
	const payload = object(decoded(p));
	const signature = fromBase64url(s);
	if (!header || !payload || !signature) return undefined;
	const alg = header.alg;
	// No extension is implemented: a header naming critical ones, or the unencoded payload's, is refused.
	if (!isAlg(alg) || "crit" in header || "b64" in header) return undefined;
	for (const jwk of keys) {
		if (!verifies(jwk)) continue;
		if (algOf(jwk) !== alg || !algorithms[alg].fits(jwk)) continue;
		if (header.kid !== undefined && jwk.kid !== undefined && header.kid !== jwk.kid) continue;
		try {
			const { alg: _alg, key_ops: _ops, use: _use, ...material } = jwk;
			const key = await crypto.subtle.importKey("jwk", material, algorithms[alg].import, false, [
				"verify",
			]);
			if (await crypto.subtle.verify(algorithms[alg].verify, key, signature, utf8(`${h}.${p}`)))
				return { header, payload };
		} catch {}
	}
	return undefined;
}
