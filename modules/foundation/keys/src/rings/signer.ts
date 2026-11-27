import type { KeyObject } from "node:crypto";
import type { Log } from "@mod/kernel";
import { tokens } from "@mod/transparency-wire";
import { compactVerify, decodeProtectedHeader, type ProtectedHeaderParameters } from "jose";
import type { KeyHolder, Prepared, Ring as RingName, Signed, VerifyResult } from "../contract.ts";
import { isCanonicalJws } from "../material/jws.ts";
import { expired, type Ring, type RingKey } from "./ring.ts";

const decoder = new TextDecoder("utf-8", { fatal: true });
const segment = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");

function headerOf(token: string): ProtectedHeaderParameters | undefined {
	try {
		return decodeProtectedHeader(token);
	} catch {
		return undefined;
	}
}

async function verifiedPayload(token: string, key: RingKey): Promise<Uint8Array | undefined> {
	try {
		return (await compactVerify(token, key.key, { algorithms: [key.alg] })).payload;
	} catch {
		return undefined;
	}
}

/** A JSON text's value, read by the one reading that refuses a member named twice; none for any other text. */
export function jsonOf(bytes: Uint8Array): unknown {
	let text: string;
	try {
		text = decoder.decode(bytes);
	} catch {
		return undefined;
	}
	try {
		const read = tokens.parse(text);
		return "value" in read ? read.value : undefined;
	} catch {
		// The reader walks by a stack and throws on no JSON text; should one ever throw, it is no JSON this reads.
		return undefined;
	}
}

/**
 * The key paths of the claims whose value is null at any depth, an object's member or an array's
 * element, in the order written; by a stack, never recursion, so claims however deep are walked.
 */
function nullClaims(value: unknown): string[] {
	const found: string[] = [];
	const left: [unknown, string][] = [];
	const under = (at: unknown, path: string) => {
		const inside: [unknown, string][] = Array.isArray(at)
			? [...at.entries()].map(([i, item]) => [item, `${path}[${i}]`])
			: typeof at === "object" && at !== null
				? Object.entries(at).map(([key, claim]) => [claim, path ? `${path}.${key}` : key])
				: [];
		for (let i = inside.length - 1; i >= 0; i--) left.push(inside[i] as [unknown, string]);
	};
	under(value, "");
	for (let next = left.pop(); next; next = left.pop()) {
		const [at, path] = next;
		if (at === null) found.push(path);
		else under(at, path);
	}
	return found;
}

const isObject = (value: unknown) =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** Each curve's signature, two of its coordinates (RFC 7518 §3.4); an Edwards key's, as RFC 8032 writes it. */
const curveSignature: Readonly<Record<string, number>> = {
	prime256v1: 64,
	secp384r1: 96,
	secp521r1: 132,
};
const edwardsSignature: Readonly<Record<string, number>> = { ed25519: 64, ed448: 114 };

/**
 * How many bytes a key's signature takes: an RSA key's modulus, a curve's coordinates, an Edwards
 * key's. A key of another kind is a TypeError: a length guessed short would let a token past its size.
 */
function signatureLengthOf(key: KeyObject): number {
	const type = key.asymmetricKeyType ?? "";
	const details = key.asymmetricKeyDetails;
	const modulus = details?.modulusLength;
	const length =
		type === "rsa" || type === "rsa-pss"
			? modulus && Math.ceil(modulus / 8)
			: type === "ec"
				? curveSignature[details?.namedCurve ?? ""]
				: edwardsSignature[type];
	if (!length) throw new TypeError(`keys: no signature length is known for a ${type} key`);
	return length;
}

/** Signing and verifying under a `typ`, with one ring's keys, through the holder. */
export interface RingSigner {
	prepare(typ: string): Prepared;
	sign(prepared: Prepared, payload: Uint8Array): Promise<Signed>;
	verify(token: string, typ: string): Promise<VerifyResult>;
}

export function ringSigner(
	name: RingName,
	ring: Ring,
	holder: KeyHolder,
	now: () => number,
	log: Log,
): RingSigner {
	const byKid = new Map(ring.verifying.map((k) => [k.kid, k]));
	// Only what this signer prepared is signed, so the header is the one fixed, whatever came between.
	const issued = new WeakSet<Prepared>();
	return {
		prepare: (typ) => {
			const { kid, alg, key } = ring.signing;
			const header = Object.freeze({ alg, typ, kid });
			const headerText = JSON.stringify(header);
			const signatureLength = signatureLengthOf(key);
			const prepared = Object.freeze({ ring: name, header, headerText, signatureLength });
			issued.add(prepared);
			return prepared;
		},
		sign: async (prepared, payload) => {
			if (!issued.has(prepared)) {
				throw new TypeError("keys: a signature is made only under a header this ring prepared");
			}
			const claims = jsonOf(payload);
			if (!isObject(claims)) {
				throw new TypeError("keys: the payload is no JSON object, or names a member twice");
			}
			// No claim is written as null (OpenID Connect Core §13.3): one with no value is left out.
			const nulls = nullClaims(claims);
			if (nulls.length > 0) {
				// The caller's failure is logged by its kind alone; this names the claims, never their values.
				log.error("keys.null_claims", { claims: nulls.join(" ") });
				throw new TypeError(`keys: claims are null: ${nulls.join(" ")}`);
			}
			const { kid, alg } = prepared.header;
			const input = `${segment(prepared.headerText)}.${segment(payload)}`;
			const answer = await holder.sign(kid, alg, new TextEncoder().encode(input));
			if (answer.kind === "withdrawn") {
				log.warn("keys.withdrawn", { use: name, kid });
				return { kind: "withdrawn" };
			}
			// The length its prepared said before signing: a holder answering another (DER for P1363) is
			// refused here, its signature never written; a fault it repeats, so no outage to try again.
			const said = prepared.signatureLength;
			if (answer.signature.length !== said) {
				const answered = String(answer.signature.length);
				log.error("keys.signature_length", { use: name, kid, said: String(said), answered });
				throw new Error("keys: its holder answered a signature of another length than prepared");
			}
			return { kind: "signed", jws: `${input}.${segment(answer.signature)}` };
		},
		verify: async (token, typ) => {
			const header = isCanonicalJws(token) ? headerOf(token) : undefined;
			if (!header) return { kind: "invalid", reason: "malformed" };
			if (header.typ !== typ) return { kind: "invalid", reason: "typ" };
			const key = typeof header.kid === "string" ? byKid.get(header.kid) : undefined;
			if (!key) return { kind: "invalid", reason: "kid_unknown" };
			if (expired(key, now)) return { kind: "invalid", reason: "kid_expired" };
			const payload = await verifiedPayload(token, key);
			if (!payload) return { kind: "invalid", reason: "signature" };
			const claims = jsonOf(payload);
			// Only a key holder can sign a payload that is not JSON; it is answered as a bad signature.
			if (claims === undefined) return { kind: "invalid", reason: "signature" };
			return { kind: "valid", claims: Object.freeze(claims) as Readonly<Record<string, unknown>> };
		},
	};
}

/** The access token type, however written: `tokens` alone signs and verifies it, through accessTokenSigning. */
const isAccessTokenType = (typ: string) =>
	(typ.split(";", 1)[0] ?? "")
		.trim()
		.toLowerCase()
		.replace(/^application\//, "") === "at+jwt";

/** Refuses the access token type, as the caller's TypeError. */
export function refusingAccessTokens(typ: string): void {
	if (isAccessTokenType(typ)) {
		throw new TypeError("keys: an access token is signed and verified through accessTokenSigning");
	}
}
