import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import {
	cose,
	decodeAttestationObject,
	decodeClientDataJSON,
	decodeCredentialPublicKey,
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

/**
 * A credential's key, its stored COSE key in base64url, as Node's crypto verifies with it, and the
 * hash its signature takes (none for EdDSA); throws for a key of an algorithm not among `taken`
 * (COSE ids), one whose key type or curve is not its algorithm's, and an RSA key under 2048 bits.
 */
function keyOf(
	publicKey: string,
	taken: readonly number[],
): { readonly key: KeyObject; readonly hash: string | null } {
	if (!/^[A-Za-z0-9_-]+$/.test(publicKey)) throw new TypeError("no key");
	const cose = decodeCredentialPublicKey(Buffer.from(publicKey, "base64url")) as Map<
		number,
		unknown
	>;
	const [kty, alg, crv] = [cose.get(1), cose.get(3), cose.get(-1)];
	if (typeof alg !== "number" || !taken.includes(alg))
		throw new TypeError("an algorithm not taken");
	const part = (label: number) => {
		const value = cose.get(label);
		if (!(value instanceof Uint8Array)) throw new TypeError("no key part");
		return Buffer.from(value).toString("base64url");
	};
	const jwk = (key: Record<string, string>) => createPublicKey({ key, format: "jwk" });
	if (alg === coseIds.ES256 && kty === 2 && crv === 1) {
		return { key: jwk({ kty: "EC", crv: "P-256", x: part(-2), y: part(-3) }), hash: "sha256" };
	}
	if (alg === coseIds.EdDSA && kty === 1 && crv === 6) {
		return { key: jwk({ kty: "OKP", crv: "Ed25519", x: part(-2) }), hash: null };
	}
	if (alg === coseIds.RS256 && kty === 3) {
		const key = jwk({ kty: "RSA", n: part(-1), e: part(-2) });
		if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
			throw new TypeError("a short RSA key");
		return { key, hash: "sha256" };
	}
	throw new TypeError("a key unlike its algorithm");
}

const statuses: readonly unknown[] = ["present", "supported", "notSupported"];

/**
 * The evidence check: an assertion's credential where it verifies by the stored key given, of an
 * algorithm the relying party takes, for the challenge and origin, at the relying party, with the
 * user present and verified; none otherwise. It reads what the library reads, as `assert` does,
 * and no count, backup state or handle.
 */
function evidenceCheck(rp: RelyingParty): Ceremonies["verifyAssertion"] {
	const rpIdHash = createHash("sha256").update(rp.id).digest();
	const taken = rp.algorithms.map((name) => coseIds[name]);
	const verified = (assertion: string, publicKey: string, challenge: string, origin: string) => {
		if (!isChallenge(challenge)) return undefined;
		const { key, hash } = keyOf(publicKey, taken);
		const sent = JSON.parse(assertion);
		const { id, rawId, type, response } = sent ?? {};
		if (typeof id !== "string" || id === "" || id !== rawId || type !== "public-key")
			return undefined;
		const data = clientDataOf(sent);
		if (data?.type !== "webauthn.get" || data.challenge !== challenge) return undefined;
		if (data.origin !== origin || frameRefusal(data, rp.topOrigins)) return undefined;
		const binding = data.tokenBinding as { status?: unknown } | undefined;
		if (binding !== undefined && !statuses.includes(binding?.status)) return undefined;
		const { authenticatorData, signature, clientDataJSON } = response;
		if (![authenticatorData, signature].every((s) => isoBase64URL.isBase64URL(s))) return undefined;
		const authData = isoBase64URL.toBuffer(authenticatorData);
		const { rpIdHash: named, flags } = parseAuthenticatorData(authData);
		if (!Buffer.from(named).equals(rpIdHash) || !flags.up || !flags.uv) return undefined;
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
	const keyTaken = (publicKey: string) => {
		try {
			const alg = decodeCredentialPublicKey(Buffer.from(publicKey, "base64url")).get(
				cose.COSEKEYS.alg,
			);
			return alg !== undefined && algorithms.includes(alg);
		} catch {
			return false;
		}
	};
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
			if (!keyTaken(credential.publicKey)) return refused("algorithm");
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
