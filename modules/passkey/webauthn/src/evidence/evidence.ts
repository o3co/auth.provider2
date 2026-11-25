import { createHash, verify } from "node:crypto";
import {
	decodeAttestationObject,
	isoBase64URL,
	parseAuthenticatorData,
} from "@simplewebauthn/server/helpers";
import { assertionKey } from "../keys.ts";
import {
	clientDataOf,
	frameRefusal,
	isChallenge,
	keyReadWhole,
	type RelyingParty,
} from "../reading/reading.ts";

/** The token binding statuses client data may carry. */
const statuses: readonly unknown[] = ["present", "supported", "notSupported"];

/**
 * The evidence check: an assertion's credential where it verifies by the key given, whatever the
 * relying party offers, for the challenge and origin, with the user present and verified; none
 * otherwise. It reads what the library reads, as `assert` does, and no count, backup state or handle.
 */
/** The evidence check, the rules' and a rooted refresh's: for the origin given, or with none, any it lists. */
export function evidenceCheck(rp: RelyingParty) {
	const rpIdHash = createHash("sha256").update(rp.id).digest();
	const verified = (assertion: string, publicKey: string, challenge: string, given?: string) => {
		if (!isChallenge(challenge)) return undefined;
		const { key, hash } = assertionKey(publicKey);
		const sent = JSON.parse(assertion);
		const { id, rawId, type, response } = sent ?? {};
		if (typeof id !== "string" || id === "" || id !== rawId || type !== "public-key")
			return undefined;
		const data = clientDataOf(sent);
		if (data?.type !== "webauthn.get" || data.challenge !== challenge) return undefined;
		// The origin asked, and one the relying party lists: closed where the two settings drift.
		const origin = given ?? data.origin;
		if (data.origin !== origin || typeof origin !== "string" || !rp.origins.includes(origin))
			return undefined;
		if (frameRefusal(data, rp.topOrigins)) return undefined;
		const binding = data.tokenBinding as { status?: unknown } | undefined;
		if (binding !== undefined && !statuses.includes(binding?.status)) return undefined;
		const { authenticatorData, signature, clientDataJSON } = response;
		if (![authenticatorData, signature].every((s) => isoBase64URL.isBase64URL(s))) return undefined;
		const authData = isoBase64URL.toBuffer(authenticatorData);
		const { rpIdHash: named, flags } = parseAuthenticatorData(authData);
		if (!Buffer.from(named).equals(rpIdHash) || !flags.up || !flags.uv) return undefined;
		// Backed up yet not backup eligible, which the library refuses at assert.
		if (flags.bs && !flags.be) return undefined;
		const clientDataHash = createHash("sha256")
			.update(isoBase64URL.toBuffer(clientDataJSON))
			.digest();
		const signed = Buffer.concat([authData, clientDataHash]);
		return verify(hash, signed, key, isoBase64URL.toBuffer(signature))
			? { credential: id }
			: undefined;
	};
	return (assertion: string, publicKey: string, challenge: string, origin?: string) => {
		// Anything it cannot read, the key included, is evidence that does not verify.
		try {
			return verified(assertion, publicKey, challenge, origin);
		} catch {
			return undefined;
		}
	};
}

/** A `create()` response's credential id and new key, read from its authenticator data; none where it does not read. */
export function attestedKey(response: string) {
	try {
		const sent = JSON.parse(response);
		const { id, rawId, type } = sent ?? {};
		if (typeof id !== "string" || id === "" || id !== rawId || type !== "public-key")
			return undefined;
		const attestationObject = isoBase64URL.toBuffer(sent.response.attestationObject);
		const authData = decodeAttestationObject(attestationObject).get("authData") as Uint8Array;
		const { credentialID, credentialPublicKey } = parseAuthenticatorData(new Uint8Array(authData));
		if (!credentialID || !credentialPublicKey) return undefined;
		if (isoBase64URL.fromBuffer(credentialID) !== id) return undefined;
		if (!keyReadWhole(attestationObject, credentialPublicKey)) return undefined;
		return { credential: id, publicKey: Buffer.from(credentialPublicKey).toString("base64url") };
	} catch {
		// Anything it cannot read is a response of no key.
		return undefined;
	}
}
