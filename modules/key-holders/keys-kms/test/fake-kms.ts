import {
	constants,
	createPublicKey,
	diffieHellman,
	type KeyObject,
	privateEncrypt,
	randomBytes,
} from "node:crypto";
import type {
	DeriveSharedSecretCommandInput,
	DeriveSharedSecretCommandOutput,
	GetPublicKeyCommandInput,
	GetPublicKeyCommandOutput,
	SignCommandInput,
	SignCommandOutput,
} from "@aws-sdk/client-kms";
import type { Kms } from "../src/kms.ts";

/** A key the fake KMS holds, as KMS describes one. */
export interface FakeKey {
	readonly key: KeyObject;
	readonly spec: "ECC_NIST_P256" | "RSA_2048" | "ECC_NIST_EDWARDS25519";
	readonly usage: "SIGN_VERIFY" | "KEY_AGREEMENT";
}

/** An error as the SDK throws one: its name, and whether the client or the service is at fault. */
export const serviceError = (name: string, fault: "client" | "server" = "client") =>
	Object.assign(new Error(name), { name, $fault: fault, $metadata: { httpStatusCode: 400 } });

// P-256, for an ECDSA signature over a digest KMS is given: the platform signs only a message it hashes.
const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const g = {
	x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
	y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
type Point = { readonly x: bigint; readonly y: bigint } | undefined;
const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
const power = (b: bigint, e: bigint, m: bigint): bigint => {
	let result = 1n;
	for (let base = mod(b, m), rest = e; rest > 0n; rest >>= 1n, base = (base * base) % m) {
		if (rest & 1n) result = (result * base) % m;
	}
	return result;
};
const inverse = (a: bigint, m: bigint) => power(a, m - 2n, m);
function add(a: Point, b: Point): Point {
	if (!a) return b;
	if (!b) return a;
	if (a.x === b.x && mod(a.y + b.y, p) === 0n) return undefined;
	const slope =
		a.x === b.x
			? mod((3n * a.x * a.x - 3n) * inverse(2n * a.y, p), p)
			: mod((b.y - a.y) * inverse(b.x - a.x, p), p);
	const x = mod(slope * slope - a.x - b.x, p);
	return { x, y: mod(slope * (a.x - x) - a.y, p) };
}
function times(k: bigint, point: Point): Point {
	let result: Point;
	for (let at = point, rest = k; rest > 0n; rest >>= 1n, at = add(at, at)) {
		if (rest & 1n) result = add(result, at);
	}
	return result;
}
const integer = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
/** A DER INTEGER of a positive value. */
const derInteger = (value: bigint) => {
	let body = Buffer.from(value.toString(16).padStart(64, "0"), "hex");
	while (body.length > 1 && body[0] === 0 && (body[1] ?? 0) < 0x80) body = body.subarray(1);
	if ((body[0] ?? 0) >= 0x80) body = Buffer.concat([Buffer.of(0), body]);
	return Buffer.concat([Buffer.of(2, body.length), body]);
};
/** An ECDSA signature over a SHA-256 digest, in DER as KMS writes it. */
function ecdsa(key: KeyObject, digest: Uint8Array): Uint8Array {
	const d = integer(Buffer.from(key.export({ format: "jwk" }).d as string, "base64url"));
	const e = integer(digest);
	for (;;) {
		const k = mod(integer(randomBytes(32)), n);
		const r = k === 0n ? 0n : mod(times(k, g)?.x ?? 0n, n);
		const s = mod(inverse(k, n) * (e + r * d), n);
		if (r === 0n || s === 0n) continue;
		const body = Buffer.concat([derInteger(r), derInteger(s)]);
		return new Uint8Array(Buffer.concat([Buffer.of(0x30, body.length), body]));
	}
}
/** SHA-256's DigestInfo, ahead of the digest in an RSASSA-PKCS1-v1_5 signature. */
const sha256Info = Buffer.from("3031300d060960864801650304020105000420", "hex");

/**
 * A fake of the KMS client keys-kms takes: the keys given, by key ARN, and aliases naming them as
 * KMS resolves one (to the key it names at the call); each call recorded; a call failing, or
 * answering what it is given, as asked.
 */
export function fakeKms(
	keys: Readonly<Record<string, FakeKey>>,
	aliasing: Readonly<Record<string, string>> = {},
) {
	const calls: { readonly command: string; readonly input: unknown }[] = [];
	const failing = new Map<string, Error>();
	const answering = new Map<string, Record<string, unknown>>();
	const aliases = new Map(Object.entries(aliasing));
	let destroyed = false;
	const keyOf = (command: string, input: { readonly KeyId: string | undefined }) => {
		calls.push({ command, input });
		const error = failing.get(command) ?? failing.get("*");
		if (error) throw error;
		const arn = aliases.get(input.KeyId ?? "") ?? input.KeyId ?? "";
		const held = keys[arn];
		if (!held) throw serviceError("NotFoundException");
		return { ...held, arn };
	};
	const kms: Kms = {
		getPublicKey: async (input: GetPublicKeyCommandInput): Promise<GetPublicKeyCommandOutput> => {
			const held = keyOf("GetPublicKey", input);
			const signs = held.usage === "SIGN_VERIFY";
			const algorithms = {
				ECC_NIST_P256: ["ECDSA_SHA_256"],
				RSA_2048: ["RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"],
				ECC_NIST_EDWARDS25519: ["ED25519_SHA_512"],
			} as const;
			return {
				$metadata: {},
				KeyId: held.arn,
				KeySpec: held.spec,
				KeyUsage: held.usage,
				PublicKey: new Uint8Array(
					createPublicKey(held.key).export({ format: "der", type: "spki" }),
				),
				...(signs
					? { SigningAlgorithms: [...algorithms[held.spec]] }
					: { KeyAgreementAlgorithms: ["ECDH"] }),
			};
		},
		sign: async (input: SignCommandInput): Promise<SignCommandOutput> => {
			const held = keyOf("Sign", input);
			const digest = input.Message ?? new Uint8Array();
			const signature =
				input.SigningAlgorithm === "ECDSA_SHA_256"
					? ecdsa(held.key, digest)
					: new Uint8Array(
							privateEncrypt(
								{ key: held.key, padding: constants.RSA_PKCS1_PADDING },
								Buffer.concat([sha256Info, digest]),
							),
						);
			return { $metadata: {}, KeyId: held.arn, Signature: signature, ...answering.get("Sign") };
		},
		deriveSharedSecret: async (
			input: DeriveSharedSecretCommandInput,
		): Promise<DeriveSharedSecretCommandOutput> => {
			const held = keyOf("DeriveSharedSecret", input);
			const peer = createPublicKey({
				key: Buffer.from(input.PublicKey ?? new Uint8Array()),
				format: "der",
				type: "spki",
			});
			return {
				$metadata: {},
				KeyId: held.arn,
				SharedSecret: new Uint8Array(diffieHellman({ privateKey: held.key, publicKey: peer })),
				...answering.get("DeriveSharedSecret"),
			};
		},
		destroy: () => {
			destroyed = true;
		},
	};
	return {
		kms,
		calls,
		/** Makes every later call of `command` (`*` for any) throw `error`, until `restore`. */
		fail: (command: string, error: Error) => failing.set(command, error),
		/** Makes every later answer of `command` carry these members in place of its own. */
		answer: (command: string, members: Record<string, unknown>) => answering.set(command, members),
		/** Points the alias at another key, as KMS's UpdateAlias does. */
		repoint: (alias: string, arn: string) => aliases.set(alias, arn),
		restore: () => {
			failing.clear();
			answering.clear();
		},
		destroyed: () => destroyed,
	};
}
