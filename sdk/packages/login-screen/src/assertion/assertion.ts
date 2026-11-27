import type { CreationPayload } from "@mod/sdk-core-wire";
import { concat, fromBase64url, sha256, textOf } from "../bytes.ts";

/** The approving key a passkey-add's creation names (V30): sdk-core-wire's form, a P-256 or Ed25519 key's JWK. */
export type ApproverKey = NonNullable<CreationPayload["creation"]["approver_key"]>;

/** Whether an assertion verifies under a key: `unsupported` where this browser verifies none of its type. */
export type Verified = "verified" | "unverified" | "unsupported";

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** A member of `of` as bytes from its base64url text; none for any other value. */
const bytesAt = (of: Record<string, unknown>, name: string) =>
	typeof of[name] === "string" ? fromBase64url(of[name]) : undefined;

/** The assertion's parts as WebAuthn's `toJSON()` writes them (§5.1.10, AuthenticationResponseJSON); none for another value. */
function partsOf(assertion: Uint8Array) {
	const text = textOf(assertion);
	if (text === undefined) return undefined;
	let read: unknown;
	try {
		read = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!isObject(read) || read.type !== "public-key" || !isObject(read.response)) return undefined;
	const authenticatorData = bytesAt(read.response, "authenticatorData");
	const clientDataJSON = bytesAt(read.response, "clientDataJSON");
	const signature = bytesAt(read.response, "signature");
	return authenticatorData && clientDataJSON && signature
		? { authenticatorData, clientDataJSON, signature }
		: undefined;
}

/** P-256's order, the bound each of r and s lies under. */
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** An integer's DER content: positive, in its shortest form, read big-endian; none for another. */
function derInteger(bytes: Uint8Array): bigint | undefined {
	if (bytes.length === 0 || bytes.length > 33 || ((bytes[0] ?? 0) & 0x80) !== 0) return undefined;
	if (bytes[0] === 0 && (bytes.length === 1 || ((bytes[1] ?? 0) & 0x80) === 0)) return undefined;
	return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

/** An ECDSA signature in WebAuthn's DER form (SEQUENCE of r and s) made WebCrypto's r ‖ s; none unless both lie in [1, n−1], strictly encoded. */
function rawEcdsa(der: Uint8Array): Uint8Array | undefined {
	if (der[0] !== 0x30 || der[1] !== der.length - 2 || der.length > 72) return undefined;
	const at = (start: number) => {
		if (der[start] !== 0x02) return undefined;
		const length = der[start + 1] ?? 0;
		const value = derInteger(der.subarray(start + 2, start + 2 + length));
		return value === undefined || start + 2 + length > der.length
			? undefined
			: { value, end: start + 2 + length };
	};
	const r = at(2);
	const s = r && at(r.end);
	if (!r || !s || s.end !== der.length) return undefined;
	if ([r.value, s.value].some((v) => v < 1n || v >= order)) return undefined;
	const fixed = (v: bigint) =>
		Uint8Array.from(v.toString(16).padStart(64, "0").match(/../g) ?? [], (h) =>
			Number.parseInt(h, 16),
		);
	return concat(fixed(r.value), fixed(s.value));
}

/** The key's import and verification by its type: P-256 by ECDSA over SHA-256, Ed25519 by EdDSA. */
function formOf(key: ApproverKey) {
	if (key.kty === "EC" && key.crv === "P-256" && key.y !== undefined)
		return {
			jwk: { kty: key.kty, crv: key.crv, x: key.x, y: key.y },
			params: { name: "ECDSA", namedCurve: "P-256" },
			verify: { name: "ECDSA", hash: "SHA-256" },
			signature: rawEcdsa,
		} as const;
	if (key.kty === "OKP" && key.crv === "Ed25519" && key.y === undefined)
		return {
			jwk: { kty: key.kty, crv: key.crv, x: key.x },
			params: { name: "Ed25519" },
			verify: { name: "Ed25519" },
			signature: (bytes: Uint8Array) => (bytes.length === 64 ? bytes : undefined),
		} as const;
	return undefined;
}

/**
 * Whether the screen's own assertion is the `get()` for this challenge (client data of type
 * `webauthn.get`, its challenge this one) and verifies under the key named: its signature over the
 * authenticator data and the SHA-256 of the client data's bytes as sent (WebAuthn §7.2 step 20).
 * Anything that does not read or import, or any failure, is `unverified`; a key type this browser
 * cannot import (Ed25519 without WebCrypto's) is `unsupported`.
 */
export async function verifiedUnder(
	assertion: Uint8Array,
	key: ApproverKey,
	challenge: string,
): Promise<Verified> {
	const parts = partsOf(assertion);
	const form = formOf(key);
	if (!parts || !form) return "unverified";
	const text = textOf(parts.clientDataJSON);
	let client: unknown;
	try {
		client = text === undefined ? undefined : JSON.parse(text);
	} catch {
		return "unverified";
	}
	if (!isObject(client) || client.type !== "webauthn.get" || client.challenge !== challenge)
		return "unverified";
	const signature = form.signature(parts.signature);
	if (!signature) return "unverified";
	let imported: CryptoKey;
	try {
		imported = await crypto.subtle.importKey("jwk", form.jwk, form.params, false, ["verify"]);
	} catch (error) {
		return (error as { name?: unknown } | null)?.name === "NotSupportedError"
			? "unsupported"
			: "unverified";
	}
	try {
		const signed = concat(parts.authenticatorData, await sha256(parts.clientDataJSON));
		return (await crypto.subtle.verify(form.verify, imported, signature as BufferSource, signed))
			? "verified"
			: "unverified";
	} catch {
		return "unverified";
	}
}
