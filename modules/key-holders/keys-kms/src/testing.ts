import {
	constants,
	createHash,
	createPublicKey,
	diffieHellman,
	type KeyObject,
	privateEncrypt,
	randomBytes,
} from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type {
	DeriveSharedSecretCommandInput,
	DeriveSharedSecretCommandOutput,
	GetPublicKeyCommandInput,
	GetPublicKeyCommandOutput,
	SignCommandInput,
	SignCommandOutput,
} from "@aws-sdk/client-kms";
import type { Kms } from "./kms.ts";

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

const sha256 = (...parts: Uint8Array[]) =>
	createHash("sha256").update(Buffer.concat(parts)).digest();
/**
 * An RSASSA-PSS signature over a SHA-256 digest, as KMS writes one (RFC 8017 §9.1.1, MGF1 with
 * SHA-256, a salt as long as the digest), for a key of 2048 bits.
 */
function pss(key: KeyObject, digest: Uint8Array): Uint8Array {
	const length = 256;
	const salt = randomBytes(32);
	const h = sha256(Buffer.alloc(8), digest, salt);
	const db = Buffer.concat([Buffer.alloc(length - 32 - 32 - 2), Buffer.of(1), salt]);
	let mask = Buffer.alloc(0);
	for (let i = 0; mask.length < db.length; i++) {
		mask = Buffer.concat([
			mask,
			sha256(h, Buffer.from([i >>> 24, i >>> 16, i >>> 8, i].map((b) => b & 255))),
		]);
	}
	const masked = db.map((byte, i) => byte ^ (mask[i] ?? 0));
	// The leftmost bit is cleared, as the encoded message holds one bit fewer than the modulus.
	masked[0] = (masked[0] ?? 0) & 0x7f;
	const encoded = Buffer.concat([masked, h, Buffer.of(0xbc)]);
	return new Uint8Array(privateEncrypt({ key, padding: constants.RSA_NO_PADDING }, encoded));
}

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
					: input.SigningAlgorithm === "RSASSA_PSS_SHA_256"
						? pss(held.key, digest)
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

const wireBlob = (value: unknown) =>
	typeof value === "string" ? new Uint8Array(Buffer.from(value, "base64")) : undefined;

/**
 * A KMS client's calls answered as KMS answers them on the wire (JSON 1.1 by `X-Amz-Target`, blobs
 * in base64), on loopback: the SDK reaches it by its endpoint setting, such as
 * `AWS_ENDPOINT_URL_KMS`, and no request's signature is checked. A call failing answers the error's
 * name as its type. `callers` is each call's access key id, as its signature names it (`Credential=`).
 */
export async function kmsServer(
	kms: Kms,
): Promise<{ readonly url: string; readonly callers: readonly string[]; close(): Promise<void> }> {
	const callers: string[] = [];
	/** The call's answer from the fake; a body that does not read as JSON is refused as KMS refuses one. */
	const answered = async (call: string, body: string) => {
		const parsed = (() => {
			try {
				return { input: JSON.parse(body || "{}") };
			} catch {
				return undefined;
			}
		})();
		if (!parsed) return { status: 400, body: { __type: "SerializationException" } };
		const { input } = parsed;
		try {
			const answer =
				call === "GetPublicKey"
					? await kms.getPublicKey(input)
					: call === "Sign"
						? await kms.sign({ ...input, Message: wireBlob(input.Message) })
						: call === "DeriveSharedSecret"
							? await kms.deriveSharedSecret({ ...input, PublicKey: wireBlob(input.PublicKey) })
							: undefined;
			if (!answer) return { status: 400, body: { __type: "UnknownOperationException" } };
			const { $metadata: _, ...members } = answer;
			const wire = Object.entries(members).map(([name, value]) => [
				name,
				value instanceof Uint8Array ? Buffer.from(value).toString("base64") : value,
			]);
			return { status: 200, body: Object.fromEntries(wire) };
		} catch (error) {
			const failed = (error ?? {}) as { name?: string; message?: string; $fault?: string };
			const status = failed.$fault === "server" ? 500 : 400;
			return {
				status,
				body: { __type: failed.name ?? "InternalFailure", message: failed.message },
			};
		}
	};
	// Every failure is held here: a request cut off while read, or a response closed before written, is dropped.
	const server = createServer((request, response) => {
		const call = String(request.headers["x-amz-target"] ?? "").replace(/^TrentService\./, "");
		callers.push(/Credential=([^/,\s]+)\//.exec(request.headers.authorization ?? "")?.[1] ?? "");
		const chunks: Buffer[] = [];
		request.on("data", (chunk: Buffer) => chunks.push(chunk));
		request.on("error", () => response.destroy());
		response.on("error", () => undefined);
		request.on("end", () => {
			void answered(call, Buffer.concat(chunks).toString("utf8"))
				.then(({ status, body }) => {
					if (response.destroyed || response.writableEnded) return;
					const text = JSON.stringify(body);
					response.writeHead(status, { "content-type": "application/x-amz-json-1.1" });
					response.end(text);
				})
				// An answer that does not serialize, or a write that fails, ends the connection, never the host.
				.catch(() => response.destroy());
		});
	});
	await new Promise<void>((listening) => server.listen(0, "127.0.0.1", listening));
	const { port } = server.address() as AddressInfo;
	return {
		url: `http://127.0.0.1:${port}`,
		callers,
		close: () =>
			new Promise<void>((closed) => {
				server.closeAllConnections();
				server.close(() => closed());
			}),
	};
}
