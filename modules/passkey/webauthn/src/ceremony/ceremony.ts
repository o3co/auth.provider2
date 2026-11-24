import { createHash, verify } from "node:crypto";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import {
	decodeAttestationObject,
	decodeClientDataJSON,
	isoBase64URL,
	isoCBOR,
	parseAuthenticatorData,
} from "@simplewebauthn/server/helpers";
import type {
	Asserted,
	Ceremonies,
	CeremonyRefusal,
	Credential,
	Verification,
} from "../contract.ts";
import { assertionKey, passkeyKey } from "../keys.ts";

/** The signature algorithms a credential may use, by the names `keys` gives them. */
export const algorithmNames = ["EdDSA", "ES256", "RS256"] as const;
export type Algorithm = (typeof algorithmNames)[number];

/** Each algorithm as COSE names it. */
const coseIds: Readonly<Record<Algorithm, number>> = { EdDSA: -8, ES256: -7, RS256: -257 };

export interface RelyingParty {
	readonly id: string;
	readonly name: string;
	readonly origins: readonly string[];
	readonly topOrigins: readonly string[];
	/** The algorithms a credential may use, in the order creation options offer them. */
	readonly algorithms: readonly Algorithm[];
}

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** The client data as the library decodes it; none when that is not a JSON object. */
function clientDataOf(response: unknown): Readonly<Record<string, unknown>> | undefined {
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

/** The challenge a response answers, read as its verification reads it. */
export function challengeOf(response: unknown): string | undefined {
	const challenge = clientDataOf(response)?.challenge;
	return typeof challenge === "string" ? challenge : undefined;
}

/** The library's messages for a refusal, by how they start; any other refusal is `malformed`. */
const refusals: readonly (readonly [string, CeremonyRefusal])[] = [
	["Unexpected public key alg ", "algorithm"],
	["Unexpected registration response origin ", "origin"],
	["Unexpected authentication response origin ", "origin"],
	["Unexpected registration response challenge ", "challenge"],
	["Unexpected authentication response challenge ", "challenge"],
	["Unexpected RP ID hash", "rp"],
	["User verification", "user-verification"],
];
const refusalOf = (error: unknown): CeremonyRefusal =>
	refusals.find(([start]) => error instanceof Error && error.message.startsWith(start))?.[1] ??
	"malformed";

const refused = (reason: CeremonyRefusal) => ({ kind: "refused" as const, reason });

/** Whether a challenge is 32 bytes in their one unpadded base64url spelling. */
const isChallenge = (challenge: unknown): challenge is string =>
	typeof challenge === "string" &&
	/^[A-Za-z0-9_-]{43}$/.test(challenge) &&
	Buffer.from(challenge, "base64url").toString("base64url") === challenge;

/** The challenge given, which is 32 bytes in their one unpadded base64url spelling; throws on any other value. */
function given(challenge: unknown): string {
	if (isChallenge(challenge)) return challenge;
	throw new TypeError("a challenge is 32 bytes, unpadded base64url");
}

/** Why client data's frame is refused, by the pages that may frame a ceremony; none where it is not. */
function frameRefusal(
	data: Readonly<Record<string, unknown>>,
	topOrigins: readonly string[],
): CeremonyRefusal | undefined {
	// With no page listed, a frame is refused even when the browser names no page.
	if (data.crossOrigin === true && topOrigins.length === 0) return "top-origin";
	if (data.topOrigin === undefined) return undefined;
	const listed = typeof data.topOrigin === "string" && topOrigins.includes(data.topOrigin);
	return data.crossOrigin === true && listed ? undefined : "top-origin";
}

const statuses: readonly unknown[] = ["present", "supported", "notSupported"];

/**
 * The evidence check: an assertion's credential where it verifies by the key given, whatever the
 * relying party offers, for the challenge and origin, with the user present and verified; none
 * otherwise. It reads what the library reads, as `assert` does, and no count, backup state or handle.
 */
function evidenceCheck(rp: RelyingParty): Ceremonies["verifyAssertion"] {
	const rpIdHash = createHash("sha256").update(rp.id).digest();
	const verified = (assertion: string, publicKey: string, challenge: string, origin: string) => {
		if (!isChallenge(challenge)) return undefined;
		const { key, hash } = assertionKey(publicKey);
		const sent = JSON.parse(assertion);
		const { id, rawId, type, response } = sent ?? {};
		if (typeof id !== "string" || id === "" || id !== rawId || type !== "public-key")
			return undefined;
		const data = clientDataOf(sent);
		if (data?.type !== "webauthn.get" || data.challenge !== challenge) return undefined;
		// The origin asked, and one the relying party lists: closed where the two settings drift.
		if (data.origin !== origin || !rp.origins.includes(origin)) return undefined;
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
	return (assertion, publicKey, challenge, origin) => {
		// Anything it cannot read, the key included, is evidence that does not verify.
		try {
			return verified(assertion, publicKey, challenge, origin);
		} catch {
			return undefined;
		}
	};
}

/** The verification asked: weakened only where `preferred` or `discouraged` is, `required` for any other value. */
const verificationOf = (v: unknown): Verification =>
	v === "preferred" || v === "discouraged" ? v : "required";

/** The library's answer, or the refusal its error names. */
async function libraryAnswer<T extends object>(
	verify: () => Promise<T>,
): Promise<T | CeremonyRefusal> {
	try {
		return await verify();
	} catch (error) {
		return refusalOf(error);
	}
}

type RegistrationResponse = Parameters<typeof verifyRegistrationResponse>[0]["response"];

/**
 * The response as a `none` attestation of its `authData` alone: no attestation is asked for, so the
 * statement sent never reaches the library. Throws on an object that is not a map, which is `malformed`.
 */
function statementDropped(response: unknown): RegistrationResponse {
	// The library checks the shape it reads.
	const sent = response as RegistrationResponse;
	const decoded: unknown = decodeAttestationObject(
		isoBase64URL.toBuffer(sent.response.attestationObject),
	);
	if (!(decoded instanceof Map)) throw new TypeError("the attestation object is not a map");
	const kept = new Map<string, Parameters<typeof isoCBOR.encode>[0]>([
		["fmt", "none"],
		["attStmt", new Map()],
		["authData", decoded.get("authData")],
	]);
	const attestationObject = isoBase64URL.fromBuffer(isoCBOR.encode(kept));
	return { ...sent, response: { ...sent.response, attestationObject } };
}

/** Whether a new key is in its one COSE_Key form, the very bytes after the credential id (offset 55 + its length). */
function keyReadWhole(attestationObject: Uint8Array, publicKey: Uint8Array): boolean {
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
	const extensions: unknown = isoCBOR.decodeFirst(rest);
	return extensions instanceof Map && Buffer.from(isoCBOR.encode(extensions)).equals(rest);
}

// The client's transports, which the library passes on unchecked: a short list of short strings.
const hintOf = (value: unknown): string[] | undefined =>
	Array.isArray(value) &&
	value.length <= 8 &&
	value.every((t) => typeof t === "string" && t.length <= 32)
		? [...value]
		: undefined;

export function ceremoniesFor(rp: RelyingParty): Ceremonies {
	const algorithms = rp.algorithms.map((name) => coseIds[name]);
	/** Whether a kept credential's key is of an algorithm taken; one that cannot be read is not. */
	/** Before the library: a challenge other than the one given, and a frame not listed. */
	const precheck = (response: unknown, challenge: string): CeremonyRefusal | undefined => {
		const data = clientDataOf(response);
		if (!data) return "malformed";
		if (data.challenge !== challenge) return "challenge";
		return frameRefusal(data, rp.topOrigins);
	};
	const expected = (challenge: string, v: Verification | undefined) => ({
		expectedChallenge: challenge,
		expectedOrigin: [...rp.origins],
		expectedRPID: rp.id,
		requireUserVerification: verificationOf(v) === "required",
	});
	return {
		verifyAssertion: evidenceCheck(rp),
		creation: (challenge, user, exclude, v, asked = {}) => {
			const discoverable = asked.discoverable ?? true;
			return {
				rp: { id: rp.id, name: rp.name },
				user: { id: user.handle, name: user.name, displayName: user.name },
				challenge: given(challenge),
				pubKeyCredParams: algorithms.map((alg) => ({ alg, type: "public-key" })),
				attestation: "none",
				excludeCredentials: exclude.map((id) => ({ id, type: "public-key" })),
				// Passkeys are asked for with no credential listed, which reaches only a discoverable one.
				authenticatorSelection: {
					residentKey: discoverable ? "required" : "discouraged",
					requireResidentKey: discoverable,
					userVerification: verificationOf(v),
				},
			};
		},
		attest: async (response, challenge, handle, v) => {
			const early = precheck(response, given(challenge));
			if (early) return refused(early);
			const verified = await libraryAnswer(() =>
				verifyRegistrationResponse({
					response: statementDropped(response),
					...expected(challenge, v),
					supportedAlgorithmIDs: algorithms,
				}),
			);
			if (typeof verified === "string") return refused(verified);
			const info = verified.registrationInfo;
			if (!verified.verified || !info) return refused("signature");
			if (!keyReadWhole(info.attestationObject, info.credential.publicKey))
				return refused("malformed");
			const transports = hintOf(info.credential.transports);
			return {
				kind: "attested",
				credential: {
					id: info.credential.id,
					publicKey: base64url(info.credential.publicKey),
					signCount: info.credential.counter,
					userHandle: handle,
					backupEligible: info.credentialDeviceType === "multiDevice",
					backedUp: info.credentialBackedUp,
					...(transports ? { transports } : {}),
				},
			};
		},
		request: (challenge, allow, v) => ({
			challenge: given(challenge),
			rpId: rp.id,
			allowCredentials: allow.map((c) => ({
				id: c.id,
				type: "public-key",
				...(c.transports ? { transports: c.transports } : {}),
			})),
			userVerification: verificationOf(v),
		}),
		assert: async (response, { challenge, named }, credential, v) => {
			const early = precheck(response, given(challenge));
			if (early) return refused(early);
			const answered = response as Parameters<typeof verifyAuthenticationResponse>[0]["response"];
			if (answered.id !== credential.id) return refused("malformed");
			// The library checks no algorithm at assertion: a key of one no longer taken is refused here.
			if (!passkeyKey(credential.publicKey)) return refused("algorithm");
			const verified = await libraryAnswer(() =>
				verifyAuthenticationResponse({
					response: answered,
					...expected(challenge, v),
					// The frame was judged above; the library asks for the list to accept one at all.
					...(rp.topOrigins.length > 0 ? { expectedTopOrigin: [...rp.topOrigins] } : {}),
					// 0, so the library never judges the count before the signature; it is judged below.
					credential: {
						id: credential.id,
						publicKey: new Uint8Array(Buffer.from(credential.publicKey, "base64url")),
						counter: 0,
					},
				}),
			);
			if (typeof verified === "string") return refused(verified);
			if (!verified.verified) return refused("signature");
			return afterSignature(
				credential,
				verified.authenticationInfo,
				answered.response.userHandle,
				named === true,
			);
		},
	};
}

/** What a verified signature still has to meet: the handle, the backup eligibility, the count. */
function afterSignature(
	credential: Credential,
	info: {
		newCounter: number;
		credentialDeviceType: string;
		credentialBackedUp: boolean;
		userVerified: boolean;
	},
	userHandle: unknown,
	named: boolean,
): Asserted {
	// None carried passes only where the request named the credentials (WebAuthn §7.2 step 6):
	// one that is not discoverable may carry none, and the user was known before.
	if (userHandle === undefined || userHandle === null) {
		if (!named) return refused("user-handle");
	} else if (userHandle !== credential.userHandle) {
		return refused("user-handle");
	}
	if ((info.credentialDeviceType === "multiDevice") !== credential.backupEligible) {
		return refused("backup-eligibility");
	}
	// An authenticator that keeps no count answers 0 every time.
	const kept = info.newCounter === 0 && credential.signCount === 0;
	if (!kept && info.newCounter <= credential.signCount) return refused("sign-count");
	return {
		kind: "asserted",
		credential: { ...credential, signCount: info.newCounter, backedUp: info.credentialBackedUp },
		userVerified: info.userVerified,
	};
}
