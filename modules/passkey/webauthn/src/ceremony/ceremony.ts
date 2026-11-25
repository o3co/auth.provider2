import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { decodeAttestationObject, isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import type {
	Asserted,
	Ceremonies,
	CeremonyRefusal,
	Credential,
	Verification,
} from "../contract.ts";
import { attestedKey, evidenceCheck } from "../evidence/evidence.ts";
import { type Algorithm, passkeyKey } from "../keys.ts";
import {
	clientDataOf,
	frameRefusal,
	isChallenge,
	keyReadWhole,
	type RelyingParty,
} from "../reading/reading.ts";

export type { RelyingParty } from "../reading/reading.ts";

/** Each algorithm as COSE names it. */
const coseIds: Readonly<Record<Algorithm, number>> = { EdDSA: -8, ES256: -7, RS256: -257 };

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

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

/** The challenge given, which is 32 bytes in their one unpadded base64url spelling; throws on any other value. */
function given(challenge: unknown): string {
	if (isChallenge(challenge)) return challenge;
	throw new TypeError("a challenge is 32 bytes, unpadded base64url");
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

// The client's transports, which the library passes on unchecked: a short list of short strings.
const hintOf = (value: unknown): string[] | undefined =>
	Array.isArray(value) &&
	value.length <= 8 &&
	value.every((t) => typeof t === "string" && t.length <= 32)
		? [...value]
		: undefined;

export function ceremoniesFor(rp: RelyingParty): Ceremonies {
	const algorithms = rp.algorithms.map((name) => coseIds[name]);
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
	const evidence = evidenceCheck(rp);
	return {
		attestedKey,
		verifyAssertion: (assertion, publicKey, challenge, origin) =>
			evidence(assertion, publicKey, challenge, origin),
		reverifyAssertion: (assertion, publicKey, challenge) =>
			evidence(assertion, publicKey, challenge),
		allowsOrigin: (origin) => rp.origins.includes(origin),
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
			// The library reads a kept key loosely: one not in its one COSE_Key form is refused here.
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
