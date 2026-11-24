import { constants, verify } from "node:crypto";
import { isCanonicalJws, type Jwk, publicJwk, verifiesUnder } from "@mod/keys";

/** How each JWS algorithm verifies: its digest, and the signature's form or padding. */
const algorithms: Readonly<Record<string, Parameters<typeof verifyUnder>[1]>> = {
	ES256: { hash: "sha256", dsaEncoding: "ieee-p1363" },
	ES384: { hash: "sha384", dsaEncoding: "ieee-p1363" },
	ES512: { hash: "sha512", dsaEncoding: "ieee-p1363" },
	EdDSA: { hash: null },
	RS256: { hash: "sha256", padding: constants.RSA_PKCS1_PADDING },
	RS384: { hash: "sha384", padding: constants.RSA_PKCS1_PADDING },
	RS512: { hash: "sha512", padding: constants.RSA_PKCS1_PADDING },
	PS256: { hash: "sha256", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
	PS384: { hash: "sha384", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
	PS512: { hash: "sha512", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
};

function verifyUnder(
	input: Buffer,
	how: {
		readonly hash: string | null;
		readonly dsaEncoding?: "ieee-p1363";
		readonly padding?: number;
		readonly saltLength?: number;
	},
	key: NonNullable<ReturnType<typeof publicJwk>>["key"],
	signature: Buffer,
): boolean {
	const { hash, ...options } = how;
	try {
		return verify(hash, input, { key, ...options }, signature);
	} catch {
		return false;
	}
}

const isObject = (x: unknown): x is Record<string, unknown> =>
	x !== null && typeof x === "object" && !Array.isArray(x);

/** A JSON text as the Core's readers (`dpop`, `external-jwt`) read it, the last of a member named twice. */
const json = (text: string): unknown => {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
};

/**
 * A compact JWS verified by the one key given, under its header's `alg` where the key's kind fits
 * it, whatever `alg` or `kid` the key or the header names: its header and payload as
 * the Core's readers read them, or none. So it never refuses what the Core took (a DPoP proof's
 * key is read under the proof's `alg`, an assertion's under any its client's methods take). For a
 * JWS naming no `kid`, which `keys` does not read; it moves to `keys` once that verifies one.
 */
export function verifiedByOne(
	jws: string,
	keys: readonly unknown[],
): { readonly header: unknown; readonly payload: unknown } | undefined {
	const [jwk, ...more] = keys;
	if (!isObject(jwk) || more.length > 0 || !isCanonicalJws(jws)) return undefined;
	const [h = "", p = "", s = ""] = jws.split(".");
	const text = (part: string) => Buffer.from(part, "base64url").toString("utf8");
	const header = json(text(h));
	const payload = json(text(p));
	if (!isObject(header) || payload === undefined) return undefined;
	const { alg } = header;
	const how =
		typeof alg === "string" && Object.hasOwn(algorithms, alg) ? algorithms[alg] : undefined;
	const read = publicJwk(jwk as Jwk);
	const { alg: _own, ...unnamed } = read?.jwk ?? {};
	if (!how || !read || !verifiesUnder(unnamed as Jwk, alg as string)) return undefined;
	const signed = verifyUnder(Buffer.from(`${h}.${p}`), how, read.key, Buffer.from(s, "base64url"));
	return signed ? { header, payload } : undefined;
}
