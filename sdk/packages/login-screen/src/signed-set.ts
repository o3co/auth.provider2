import { logTyps, type ReceiverKey, type SignerSet, schemas } from "@mod/transparency-wire";
import { fromBase64url, textOf } from "./bytes.ts";
import { type Jwk, keyIdentity, verifyCompact } from "./jws.ts";

/** The objects a signer set signs that the screen reads: a status and a stateOf. */
export type SetPurpose = "status" | "stateOf";

const objectOf = (part: string | undefined): Record<string, unknown> | undefined => {
	const bytes = fromBase64url(part ?? "");
	const text = bytes && textOf(bytes);
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

/** A protocol key as WebCrypto's JWK, with its kid; members left undefined are left out. */
const jwkOf = (key: ReceiverKey, kid: string): Jwk =>
	Object.fromEntries(Object.entries({ ...key, kid }).filter(([, value]) => value !== undefined));

/**
 * An object a signer set signs (JWS JSON General Serialization, as its JSON text), where enough of
 * the set signed it: the set (as `readSet` read it) of the purpose, each signature verified with the
 * set's key of its kid under the purpose's `typ`, each key counted once by its identity (one key
 * named under two kids is one signer). Answers its payload, a JSON object, or none. The same rule
 * as rp-kit's status reading, which this package does not depend on (sdk/README).
 */
export async function readSetSigned(
	text: string,
	set: SignerSet,
	purpose: SetPurpose,
): Promise<Record<string, unknown> | undefined> {
	if (set.purpose !== purpose) return undefined;
	let envelope: unknown;
	try {
		envelope = JSON.parse(text);
	} catch {
		return undefined;
	}
	const read = schemas.setSigned.safeParse(envelope);
	if (!read.success) return undefined;
	const { payload, signatures } = read.data;
	const signed = new Set<string>();
	for (const one of signatures) {
		const header = objectOf(one.protected);
		const kid = header?.kid;
		const entry = set.keys.find((key) => key.kid === kid);
		if (!entry || typeof kid !== "string" || header?.typ !== logTyps[purpose]) continue;
		const jwk = jwkOf(entry.key, kid);
		const verified = await verifyCompact(`${one.protected}.${payload}.${one.signature}`, [jwk]);
		const identity = keyIdentity(jwk);
		if (verified && identity !== undefined) signed.add(identity);
	}
	return signed.size >= set.required ? objectOf(payload) : undefined;
}

/** A signer set read as the wire's: a copy of its own, so a caller's later change reaches nothing read; none otherwise. */
export function readSet(signers: unknown): SignerSet | undefined {
	const given = schemas.signerSet.safeParse(signers);
	return given.success ? given.data : undefined;
}

/** The identities of a set's keys ("" for one with none). */
export const setIdentities = (set: SignerSet): readonly string[] =>
	set.keys.map((entry) => keyIdentity(jwkOf(entry.key, entry.kid)) ?? "");
