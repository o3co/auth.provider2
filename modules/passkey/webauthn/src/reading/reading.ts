import { decodeAttestationObject, decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import type { CeremonyRefusal } from "../contract.ts";
import { type Algorithm, passkeyKey } from "../keys.ts";

export interface RelyingParty {
	readonly id: string;
	readonly name: string;
	readonly origins: readonly string[];
	readonly topOrigins: readonly string[];
	/** The algorithms a credential may use, in the order creation options offer them. */
	readonly algorithms: readonly Algorithm[];
}

/** The client data as the library decodes it; none when that is not a JSON object. */
export function clientDataOf(response: unknown): Readonly<Record<string, unknown>> | undefined {
	const encoded = (response as { response?: { clientDataJSON?: unknown } } | null)?.response
		?.clientDataJSON;
	if (typeof encoded !== "string") return undefined;
	try {
		const data: unknown = decodeClientDataJSON(encoded);
		return typeof data === "object" && data !== null && !Array.isArray(data)
			? (data as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}

/** Whether a challenge is 32 bytes in their one unpadded base64url spelling. */
export const isChallenge = (challenge: unknown): challenge is string =>
	typeof challenge === "string" &&
	/^[A-Za-z0-9_-]{43}$/.test(challenge) &&
	Buffer.from(challenge, "base64url").toString("base64url") === challenge;

/** Why client data's frame is refused, by the pages that may frame a ceremony; none where it is not. */
export function frameRefusal(
	data: Readonly<Record<string, unknown>>,
	topOrigins: readonly string[],
): CeremonyRefusal | undefined {
	// With no page listed, a frame is refused even when the browser names no page.
	if (data.crossOrigin === true && topOrigins.length === 0) return "top-origin";
	if (data.topOrigin === undefined) return undefined;
	const listed = typeof data.topOrigin === "string" && topOrigins.includes(data.topOrigin);
	return data.crossOrigin === true && listed ? undefined : "top-origin";
}

/** Whether a new key is in its one COSE_Key form, the very bytes after the credential id (offset 55 + its length). */
export function keyReadWhole(attestationObject: Uint8Array, publicKey: Uint8Array): boolean {
	const authData = Buffer.from(
		decodeAttestationObject(new Uint8Array(attestationObject)).get("authData") as Uint8Array,
	);
	const at = 55 + authData.readUInt16BE(53);
	const key = Buffer.from(publicKey);
	const rest = authData.subarray(at + key.length);
	if (passkeyKey(key.toString("base64url")) === undefined) return false;
	if (!authData.subarray(at, at + key.length).equals(key)) return false;
	// After the key: nothing, or where the extension flag is set, one map of extensions, read whole.
	if (((authData[32] ?? 0) & 0x80) === 0) return rest.length === 0;
	return (rest[0] ?? 0) >> 5 === 5 && itemEnd(rest, 0) === rest.length;
}

/** Where one CBOR item of definite lengths at `at` ends, on the bytes as sent; none for any other. */
function itemEnd(bytes: Buffer, at: number, depth = 0): number | undefined {
	const head = bytes[at];
	if (head === undefined || depth > 16 || (head & 31) > 27) return undefined;
	const size = (head & 31) < 24 ? 0 : 1 << ((head & 31) - 24);
	if (at + 1 + size > bytes.length) return undefined;
	const n =
		size === 0
			? head & 31
			: size === 8
				? Number(bytes.readBigUInt64BE(at + 1))
				: bytes.readUIntBE(at + 1, size);
	const next = at + 1 + size;
	const major = head >> 5;
	if (major <= 1 || major === 7) return next;
	if (major <= 3) return next + n <= bytes.length ? next + n : undefined;
	if (major === 6) return itemEnd(bytes, next, depth + 1);
	let end: number | undefined = next;
	for (let i = 0; i < (major === 5 ? 2 * n : n) && end !== undefined; i++)
		end = itemEnd(bytes, end, depth + 1);
	return end;
}
