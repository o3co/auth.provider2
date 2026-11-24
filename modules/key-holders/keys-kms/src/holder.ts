import { createHash, createPublicKey } from "node:crypto";
import type { SigningAlgorithmSpec } from "@aws-sdk/client-kms";
import { type Refusal, Unavailable } from "@mod/kernel";
import type { Held, KeyHolder } from "@mod/keys";
import type { Kms } from "./kms.ts";
import type { Section } from "./section.ts";

/** The JWS algorithms signed here, each by KMS's algorithm over a SHA-256 digest. */
const algorithms: Readonly<Record<string, SigningAlgorithmSpec>> = {
	ES256: "ECDSA_SHA_256",
	PS256: "RSASSA_PSS_SHA_256",
	RS256: "RSASSA_PKCS1_V1_5_SHA_256",
};

/** KMS's answers that say this Core may no longer use the key: its permission removed, or the key disabled. */
const withdrawing = new Set([
	"AccessDeniedException",
	"DisabledException",
	"KMSInvalidStateException",
]);
/** KMS's answers that are an outage rather than a refusal. */
const outages = new Set(["ThrottlingException", "KeyUnavailableException"]);

/** What a thrown error is: withdrawn, an outage, or neither (thrown on as it is). */
function kindOf(error: unknown): "withdrawn" | "outage" | "other" {
	const { name, $fault } = (error ?? {}) as { name?: string; $fault?: string };
	if (name !== undefined && withdrawing.has(name)) return "withdrawn";
	// What is no answer of the service at all (no fault named) is the network's.
	if ($fault === undefined || $fault === "server" || (name !== undefined && outages.has(name))) {
		return "outage";
	}
	return "other";
}

/** An answer KMS gave that is none it should: a failure, never taken for a signature or a secret. */
const malformed = (what: string) => new Error(`keys-kms: KMS answered ${what}`);

/**
 * An ECDSA signature in DER (a SEQUENCE of two INTEGERs, r and s) as a JWS writes it: r and s of 32
 * bytes each. Anything else is a failure.
 */
function rawOf(der: Uint8Array): Uint8Array {
	const bytes = Buffer.from(der);
	// A P-256 signature's SEQUENCE is under 128 bytes, so its length is one byte.
	if (bytes[0] !== 0x30 || bytes[1] !== bytes.length - 2)
		throw malformed("a signature that is no DER");
	let at = 2;
	const part = () => {
		const length = bytes[at + 1] ?? 0;
		if (bytes[at] !== 0x02 || length < 1 || length > 33 || at + 2 + length > bytes.length) {
			throw malformed("a signature that is no DER");
		}
		const value = bytes.subarray(at + 2, at + 2 + length);
		at += 2 + length;
		const trimmed = length === 33 && value[0] === 0 ? value.subarray(1) : value;
		if (trimmed.length > 32) throw malformed("a signature that is no DER");
		return Buffer.concat([Buffer.alloc(32 - trimmed.length), trimmed]);
	};
	const raw = Buffer.concat([part(), part()]);
	if (at !== bytes.length) throw malformed("a signature that is no DER");
	return new Uint8Array(raw);
}

/** Why a key's public half cannot be read, as a refusal says it. */
function unread(error: unknown): string {
	const { name } = (error ?? {}) as { name?: string };
	if (name === "NotFoundException") return "no such key in KMS";
	if (name === "AccessDeniedException") {
		return "the Core may not read the key's public half (kms:GetPublicKey)";
	}
	return kindOf(error) === "outage"
		? "KMS gave no answer for the key's public half"
		: "KMS refused to give the key's public half";
}

/** Reads each key's public half from KMS at boot into a holder whose operations are KMS's, or why boot is refused. */
export async function kmsHolder(
	s: Section,
	kms: Kms,
): Promise<KeyHolder | { readonly refused: Refusal[] }> {
	const refused: Refusal[] = [];
	const held = new Map<string, Held & { readonly keyId: string }>();
	for (const [i, entry] of s.keys.entries()) {
		const read = await kms.getPublicKey({ KeyId: entry["key-id"] }).catch((error: unknown) => {
			refused.push({ where: `keys-kms.keys.${i}.key-id`, reason: unread(error) });
			return undefined;
		});
		if (read === undefined) continue;
		// The key the id names now: an alias may be pointed elsewhere later, and the public half read here stays this key's.
		if (!read.KeyId || !read.PublicKey) {
			refused.push({
				where: `keys-kms.keys.${i}.key-id`,
				reason: "KMS named no key or public half for it",
			});
			continue;
		}
		const signs = read.KeyUsage === "SIGN_VERIFY" ? (read.SigningAlgorithms ?? []) : [];
		held.set(entry.kid, {
			keyId: read.KeyId,
			publicKey: createPublicKey({
				key: Buffer.from(read.PublicKey),
				format: "der",
				type: "spki",
			}),
			signsUnder: Object.keys(algorithms).filter((alg) => signs.includes(algorithms[alg] as never)),
			agrees:
				read.KeyUsage === "KEY_AGREEMENT" &&
				read.KeySpec === "ECC_NIST_P256" &&
				(read.KeyAgreementAlgorithms ?? []).includes("ECDH"),
		});
	}
	if (refused.length > 0) return { refused };
	const keyIdOf = (kid: string) => {
		const key = held.get(kid);
		if (key === undefined) throw new TypeError(`keys-kms: no key of kid ${kid}`);
		return key.keyId;
	};
	/** A call of KMS: its answer, `withdrawn`, or an outage thrown as one. */
	const called = async <T>(call: () => Promise<T>): Promise<T | "withdrawn"> => {
		try {
			return await call();
		} catch (error) {
			const kind = kindOf(error);
			if (kind === "withdrawn") return "withdrawn";
			if (kind === "outage") throw new Unavailable("kms");
			throw error;
		}
	};
	return {
		// KMS's key policy and IAM take Sign and DeriveSharedSecret from the Core's role outside it.
		// Its calls are recorded in the key's own account: nothing here counts them outside the Core's.
		powers: { withdrawable: true, countedOutside: false },
		held: (kid) => {
			const key = held.get(kid);
			return key && { publicKey: key.publicKey, signsUnder: key.signsUnder, agrees: key.agrees };
		},
		sign: async (kid, alg, input) => {
			const algorithm = algorithms[alg];
			if (algorithm === undefined) throw new TypeError(`keys-kms: does not sign under ${alg}`);
			const keyId = keyIdOf(kid);
			const answer = await called(() =>
				kms.sign({
					KeyId: keyId,
					Message: new Uint8Array(createHash("sha256").update(input).digest()),
					MessageType: "DIGEST",
					SigningAlgorithm: algorithm,
				}),
			);
			if (answer === "withdrawn") return { kind: "withdrawn" };
			const signature = answer.Signature;
			if (!signature?.length) throw malformed("no signature");
			return { kind: "signed", signature: alg === "ES256" ? rawOf(signature) : signature };
		},
		agree: async (kid, peer) => {
			const keyId = keyIdOf(kid);
			const answer = await called(() =>
				kms.deriveSharedSecret({
					KeyId: keyId,
					KeyAgreementAlgorithm: "ECDH",
					PublicKey: new Uint8Array(peer.export({ format: "der", type: "spki" })),
				}),
			);
			if (answer === "withdrawn") return { kind: "withdrawn" };
			if (answer.SharedSecret?.length !== 32) throw malformed("no P-256 shared secret");
			return { kind: "agreed", shared: answer.SharedSecret };
		},
	};
}
