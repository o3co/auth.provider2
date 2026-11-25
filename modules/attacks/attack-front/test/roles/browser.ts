import { createPublicKey } from "node:crypto";
import { softwareAuthenticator } from "@mod/webauthn/testing";

/**
 * The browser the screen runs in, as far as the harness needs it: `navigator.credentials` over a
 * software authenticator, its options and answers in WebAuthn's JSON (RFC 4648 base64url), and the new
 * key's SPKI as `getPublicKey()` gives it.
 */

const b64u = (bytes: ArrayBuffer | ArrayBufferView) =>
	Buffer.from(
		bytes instanceof ArrayBuffer
			? bytes
			: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
	).toString("base64url");

type Cbor = number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>;

/** CBOR's few kinds WebAuthn uses (integers, bytes, text, lists, maps): one item and where it ends. */
function cbor(bytes: Uint8Array, at = 0): { value: Cbor; end: number } {
	const first = bytes[at] ?? 0;
	const major = first >> 5;
	const info = first & 31;
	let n = info;
	let next = at + 1;
	if (info === 24) [n, next] = [bytes[at + 1] ?? 0, at + 2];
	else if (info === 25) [n, next] = [((bytes[at + 1] ?? 0) << 8) | (bytes[at + 2] ?? 0), at + 3];
	else if (info > 25) throw new Error("a CBOR length this reader does not take");
	if (major === 0) return { value: n, end: next };
	if (major === 1) return { value: -1 - n, end: next };
	if (major === 2) return { value: bytes.subarray(next, next + n), end: next + n };
	if (major === 3)
		return { value: Buffer.from(bytes.subarray(next, next + n)).toString("utf8"), end: next + n };
	if (major === 4) {
		const items: Cbor[] = [];
		for (let i = 0; i < n; i++) {
			const item = cbor(bytes, next);
			items.push(item.value);
			next = item.end;
		}
		return { value: items, end: next };
	}
	if (major === 5) {
		const map = new Map<Cbor, Cbor>();
		for (let i = 0; i < n; i++) {
			const key = cbor(bytes, next);
			const value = cbor(bytes, key.end);
			map.set(key.value, value.value);
			next = value.end;
		}
		return { value: map, end: next };
	}
	throw new Error("a CBOR kind this reader does not take");
}

/** The new key in an attestation object, as `getPublicKey()` (its SPKI) and `getPublicKeyAlgorithm()` give it. */
export function attestedKey(attestationObject: string): { spki: Uint8Array; alg: number } {
	const object = cbor(Buffer.from(attestationObject, "base64url")).value as Map<Cbor, Cbor>;
	const authData = object.get("authData") as Uint8Array;
	// rpIdHash 32, flags 1, count 4, aaguid 16, the id's length 2 and the id, then the COSE_Key.
	const idLength = ((authData[53] ?? 0) << 8) | (authData[54] ?? 0);
	const cose = cbor(authData, 55 + idLength).value as Map<Cbor, Cbor>;
	const alg = cose.get(3) as number;
	if (alg !== -7) throw new Error("the harness's screen reads ES256 keys alone");
	const jwk = {
		kty: "EC",
		crv: "P-256",
		x: b64u(cose.get(-2) as Uint8Array),
		y: b64u(cose.get(-3) as Uint8Array),
	};
	const spki = createPublicKey({ key: jwk, format: "jwk" }).export({ type: "spki", format: "der" });
	return { spki: new Uint8Array(spki), alg };
}

/** A browser at `origin` holding a software authenticator. */
export function browser(origin: string) {
	const authenticator = softwareAuthenticator();
	const at = { origin };
	return {
		/** The origin the page is served from. */
		origin,
		/** `navigator.credentials.create`: the response's JSON as the page sends it, its credential id and new key. */
		create: (options: PublicKeyCredentialCreationOptions) => {
			const made = authenticator.create(
				{
					rp: { id: options.rp.id ?? "" },
					user: { id: b64u(options.user.id as ArrayBufferView) },
					challenge: b64u(options.challenge as ArrayBufferView),
					pubKeyCredParams: options.pubKeyCredParams,
					excludeCredentials: (options.excludeCredentials ?? []).map((c) => ({
						type: c.type,
						id: b64u(c.id as ArrayBufferView),
					})),
					authenticatorSelection: {
						residentKey: options.authenticatorSelection?.residentKey ?? "preferred",
						userVerification: options.authenticatorSelection?.userVerification ?? "preferred",
					},
				},
				at,
			) as { id: string; response: { attestationObject: string } };
			return {
				json: JSON.stringify(made),
				id: made.id,
				...attestedKey(made.response.attestationObject),
			};
		},
		/** `navigator.credentials.get`: the assertion's JSON as the page sends it. */
		get: (options: PublicKeyCredentialRequestOptions) =>
			JSON.stringify(
				authenticator.get(
					{
						challenge: b64u(options.challenge as ArrayBufferView),
						...(options.rpId !== undefined && { rpId: options.rpId }),
						allowCredentials: (options.allowCredentials ?? []).map((c) => ({
							type: c.type,
							id: b64u(c.id as ArrayBufferView),
						})),
						userVerification: options.userVerification ?? "preferred",
					},
					at,
				),
			),
	};
}

export type Browser = ReturnType<typeof browser>;
