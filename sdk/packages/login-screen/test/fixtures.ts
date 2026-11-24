import type { Jwk } from "../src/jws.ts";

/** Test helpers: keys from raw scalars and points, as the vectors give them. */
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** A P-256 key pair from its secret scalar and its uncompressed point, for ECDH or ECDSA. */
export async function pointKeyPair(
	secret: Uint8Array,
	point: Uint8Array,
	use: "ECDH" | "ECDSA",
): Promise<CryptoKeyPair> {
	const jwk = {
		kty: "EC",
		crv: "P-256",
		x: b64url(point.subarray(1, 33)),
		y: b64url(point.subarray(33, 65)),
	};
	const algorithm = { name: use, namedCurve: "P-256" };
	const usages: KeyUsage[] = use === "ECDH" ? ["deriveBits"] : ["sign"];
	return {
		privateKey: await crypto.subtle.importKey(
			"jwk",
			{ ...jwk, d: b64url(secret) },
			algorithm,
			false,
			usages,
		),
		publicKey: await crypto.subtle.importKey(
			"jwk",
			jwk,
			algorithm,
			true,
			use === "ECDH" ? [] : ["verify"],
		),
	};
}

const json = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** The algorithms a test signs with: WebCrypto's parameters and the JWK it publishes. */
export const testAlgorithms = {
	ES256: {
		generate: { name: "ECDSA", namedCurve: "P-256" },
		sign: { name: "ECDSA", hash: "SHA-256" },
	},
	EdDSA: { generate: { name: "Ed25519" }, sign: { name: "Ed25519" } },
	RS256: {
		generate: {
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: Uint8Array.of(1, 0, 1),
			hash: "SHA-256",
		},
		sign: { name: "RSASSA-PKCS1-v1_5" },
	},
	PS256: {
		generate: {
			name: "RSA-PSS",
			modulusLength: 2048,
			publicExponent: Uint8Array.of(1, 0, 1),
			hash: "SHA-256",
		},
		sign: { name: "RSA-PSS", saltLength: 32 },
	},
} as const;
export type TestAlg = keyof typeof testAlgorithms;

/** A signing key of the algorithm, its public JWK carrying `alg` and `kid`. */
export async function signingKey(alg: TestAlg, kid = `${alg}-1`) {
	const pair = (await crypto.subtle.generateKey(testAlgorithms[alg].generate, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const { key_ops: _ops, ext: _ext, ...jwk } = exported;
	return { alg, kid, privateKey: pair.privateKey, jwk: { ...jwk, alg, kid } as Jwk };
}

/** A compact JWS of the payload, under the header given (its `alg` and `kid` the key's but where it says). */
export async function signCompact(
	key: Awaited<ReturnType<typeof signingKey>>,
	payload: unknown,
	header: Record<string, unknown> = {},
): Promise<string> {
	const input = `${json({ alg: key.alg, kid: key.kid, ...header })}.${json(payload)}`;
	const signature = await crypto.subtle.sign(
		testAlgorithms[key.alg].sign,
		key.privateKey,
		new TextEncoder().encode(input),
	);
	return `${input}.${Buffer.from(signature).toString("base64url")}`;
}
