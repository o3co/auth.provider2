import { z } from "zod";

/**
 * The contract between the login screen and the Core, which the Core holds and the screen follows;
 * the Front relays it unread. It holds the words, the payloads' schemas and the inputs a hash or a
 * signature covers; hashing, signing and sealing are each side's own.
 */

/** The wire versions a reader of this protocol speaks; a statement and a completion name one as `v`. */
export const versions = Object.freeze([1] as const);

/** The `typ` of each signed object. */
export const typs = Object.freeze({
	jar: "oauth-authz-req+jwt",
	/** Every statement a person approves (T, and the first key's creation and possession), signed by the Core's ring. */
	statement: "approval+jwt",
	/** The completion's answer, kept apart from T so neither is taken for the other. */
	completion: "completion+jwt",
	clientAssertion: "client-authentication+jwt",
	dpop: "dpop+jwt",
});

/** The purposes a statement names. */
export const purposes = Object.freeze({
	authorization: "authorization",
	creation: "creation",
	possession: "possession",
	passkeyAdd: "passkey-add",
	passkeyManage: "passkey-manage",
});

/** The HPKE suite both sides seal with, as RFC 9180 names it, and the info that tells each sealing apart. */
export const hpke = Object.freeze({
	kem: "DHKEM(P-256, HKDF-SHA256)",
	kdf: "HKDF-SHA256",
	aead: "AES-128-GCM",
	info: Object.freeze({
		completion: "auth.provider2/completion/v1",
		firstKeyRequest: "auth.provider2/first-key/request/v1",
		firstKeyCode: "auth.provider2/first-key/code/v1",
	}),
	/** The additional data a completion is sealed under: its purpose and the hash of the statement it answers. */
	completionAad: (
		purpose: "authorization" | "first-key" | "passkey-add" | "passkey-manage",
		statementHash: string,
	) => canonicalText({ purpose: `completion/${purpose}`, h: statementHash }),
});

/** An authorization's items (a closed set): a JAR with any other claim beside its envelope is refused. */
const authorizationItems = Object.freeze([
	"client_id",
	"redirect_uri",
	"response_type",
	"response_mode",
	"state",
	"scope",
	"resource",
	"claims",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"dpop_jkt",
] as const);
/** The items a JAR must carry, each a string that is not empty; `resource` and `claims` may be left out. */
const requiredItems = Object.freeze([
	"client_id",
	"redirect_uri",
	"response_type",
	"response_mode",
	"state",
	"scope",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"dpop_jkt",
] as const);
/** A JAR's envelope: claims that are no item, so T holds none of them (`prompt`, read by the Core before T, among them). */
const jarEnvelope = Object.freeze(["iss", "aud", "iat", "nbf", "exp", "jti", "prompt"] as const);

/** A JAR's claims as T reads them: the items, those it must carry, and its envelope. */
export const jarClaims = Object.freeze({
	items: authorizationItems,
	required: requiredItems,
	envelope: jarEnvelope,
});

/** The screen's signing key as T and the first key's requests carry it: P-256's x and y alone. */
const signingKey = z
	.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string(), y: z.string() })
	.strict();

/** The algorithms a passkey may be of, as COSE numbers them: ES256, EdDSA (Ed25519) and RS256. */
const passkeyAlgorithm = z.union([z.literal(-7), z.literal(-8), z.literal(-257)]);

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** 32 bytes in their one unpadded base64url spelling: 43 characters, the last carrying no bit past them. */
const bytes32 = z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
/** A SHA-256 thumbprint, base64url. */
const thumbprint = bytes32;

const sextet = (text: string, at: number) => alphabet.indexOf(text.charAt(at));

/**
 * An RSA modulus in its one unpadded base64url spelling, its first byte not 0 (one that is is
 * refused, never cut), of 2048 to 4096 bits, and odd.
 */
function isModulus(text: string): boolean {
	const rest = text.length % 4;
	if (!/^[A-Za-z0-9_-]+$/.test(text) || rest === 1) return false;
	// The last character's bits past the bytes (4 where a group ends in 2 characters, 2 in 3) are 0,
	// and the last byte's lowest bit, the one above them, is 1: a modulus is odd.
	const unit = rest === 2 ? 16 : rest === 3 ? 4 : 1;
	const last = sextet(text, text.length - 1);
	if (last % unit !== 0 || (last / unit) % 2 !== 1) return false;
	const bytes = ((text.length - rest) / 4) * 3 + (rest === 0 ? 0 : rest - 1);
	const high = sextet(text, 0) * 4 + (sextet(text, 1) - (sextet(text, 1) % 16)) / 16;
	// 2048 bits are 256 bytes, the first of them 128 or more; 4096 bits are 512 bytes.
	return high !== 0 && (bytes === 256 ? high >= 128 : bytes > 256 && bytes <= 512);
}

/** A passkey's public key as a JWK, its thumbprint's members alone, for each algorithm a passkey may be of. */
const passkeyJwk = z.discriminatedUnion("kty", [
	z.object({ crv: z.literal("P-256"), kty: z.literal("EC"), x: bytes32, y: bytes32 }).strict(),
	z.object({ crv: z.literal("Ed25519"), kty: z.literal("OKP"), x: bytes32 }).strict(),
	z
		.object({ e: z.literal("AQAB"), kty: z.literal("RSA"), n: z.string().refine(isModulus) })
		.strict(),
]);
export type PasskeyJwk = z.infer<typeof passkeyJwk>;

const approval = z
	.object({
		client_id: z.string().min(1),
		redirect_uri: z.string().min(1),
		response_type: z.literal("code"),
		response_mode: z.literal("form_post"),
		state: z.string().min(1),
		scope: z.string().min(1),
		resource: z.string().min(1).optional(),
		claims: z.unknown().optional(),
		nonce: z.string().min(1),
		code_challenge: z.string().min(1),
		code_challenge_method: z.literal("S256"),
		dpop_jkt: z.string().min(1),
		/** The JAR's compact bytes' SHA-256, base64url. */
		jar_hash: z.string().min(1),
	})
	.strict();

const v = z.literal(versions[0]);

/** The fields every statement carries: its version, issuer, id, issue and expiry times, and the screen's two keys. */
const common = {
	v,
	iss: z.string().min(1),
	sid: z.string().min(1),
	iat: z.number().int(),
	exp: z.number().int(),
	/** The screen's encryption key, HPKE's raw P-256 form, base64url. */
	e_enc: z.string().min(1),
	e_sig: signingKey,
};

/** The statement T of an authorization. */
const statement = z
	.object({ ...common, purpose: z.literal(purposes.authorization), approval })
	.strict();

/** The completion's answer the Core signs and seals to the screen's encryption key. */
const completion = z
	.object({
		v,
		iss: z.string().min(1),
		purpose: z.literal(purposes.authorization).optional(),
		/** T's SHA-256. */
		t_hash: z.string().min(1),
		/** The assertion's bytes' SHA-256. */
		assertion_hash: z.string().min(1),
		code: z.string().min(1),
		/** ⑤'s receipt (`receipt+jwt`), binding T, the assertion and the code. */
		receipt: z
			.string()
			.regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
			.optional(),
		iat: z.number().int(),
		exp: z.number().int(),
	})
	.strict();

/** A statement of the first key's registration: what a `create()` is for. The identifier stays out, but masked. */
const creation = z
	.object({
		...common,
		nonce: z.string().min(1),
		purpose: z.literal(purposes.creation),
		creation: z
			.object({
				/** The identifier, masked, for display alone. */
				account: z.string(),
				/** What the evidence is: the first key's mail, an approved `passkey-add`, or a T read before signing up. */
				basis: z.enum(["first-key", "passkey-add", "sign-up"]).optional(),
				/** The evidence's value the screen computes for itself, by its basis. */
				evidence: z.string().min(1),
				/** The sealed mail request's ciphertext hash, as the Core opened it: the first key's path's alone. */
				ct_hash: z.string().min(1).optional(),
				subject: z.string().min(1),
				/** The key generation of the subject this creation is signed for (reset and erasure boundaries count it), bound in the signed bytes. */
				kg: z.number().int().nonnegative(),
				options: z
					.object({
						user_id: z.string().min(1),
						rp_id: z.string().min(1),
						exclude_credentials: z.array(z.string()),
						/** The algorithms the ceremony offered, as COSE numbers them: those the new key may be of. */
						algorithms: z
							.array(passkeyAlgorithm)
							.min(1)
							.refine((list) => list.every((alg, at) => list.indexOf(alg) === at)),
					})
					.strict(),
			})
			.strict()
			.refine(
				(c) => (c.basis === undefined || c.basis === "first-key") === (c.ct_hash !== undefined),
				{
					message: "a ciphertext hash is the first key's path's alone",
				},
			),
	})
	.strict();

const management = (purpose: typeof purposes.passkeyAdd | typeof purposes.passkeyManage) =>
	z.object({ ...common, nonce: z.string().min(1), purpose: z.literal(purpose) }).strict();

/** A statement of the new key's possession: what the key's first `get()` proves. */
const possession = z
	.object({
		...common,
		nonce: z.string().min(1),
		purpose: z.literal(purposes.possession),
		possession: z
			.object({
				creation_hash: z.string().min(1),
				/** The new key's JWK thumbprint (RFC 7638), the SHA-256 of `keyThumbprintInput`, base64url. */
				key_jkt: thumbprint,
				credential_id: z.string().min(1),
				reservation_id: z.string().min(1),
			})
			.strict(),
	})
	.strict();

/** The first key's stages, each with a nonce of its own. */
const firstKeyStages = Object.freeze(["start", "mail"] as const);
export type FirstKeyStage = (typeof firstKeyStages)[number];

/** What the Core opens of the first key's start: the identifier, and a password where the deployment asks one. */
const startPlain = z
	.object({ identifier: z.string().min(1), password: z.string().optional() })
	.strict();
/** What the Core opens of the mail's side. */
const mailPlain = z
	.object({ token: z.string().min(1), identifier: z.string().min(1), code: z.string().min(1) })
	.strict();
/** What the screen opens of the start's answer, which looks alike whether the start went well or not. */
const codePlain = z.object({ code: z.string().min(1) }).strict();

const compactJws = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
/** ②'s answer: T, its get challenge (SHA-256 of `challengeInput(T, "get")`, the screen recomputes it), whether F1 may make a passkey first. */
const authorizationAnswer = z
	.object({ statement: compactJws, challenge: bytes32, create: z.boolean() })
	.strict();
const canonical = (text: string) =>
	/^[A-Za-z0-9_-]*$/.test(text) &&
	text.length % 4 !== 1 &&
	sextet(text, text.length - 1) % (text.length % 4 === 2 ? 16 : text.length % 4 === 3 ? 4 : 1) ===
		0;
const id = z.string().min(1);
const times = { iat: z.number().int(), exp: z.number().int() };
const approved = { v, iss: id, t_hash: bytes32, assertion_hash: bytes32 };
const label = z.string().regex(/^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}]{1,64}$/u);
const keyRow = z
	.object({ credential_id: id, label, created_at: z.number().int().nonnegative() })
	.strict();
const completions = Object.freeze({
	passkeyAdd: z
		.object({
			...approved,
			purpose: z.literal(purposes.passkeyAdd),
			creation: compactJws,
			...times,
		})
		.strict(),
	passkeyManage: z
		.object({
			...approved,
			purpose: z.literal(purposes.passkeyManage),
			keys: z
				.array(keyRow)
				.max(64)
				.refine((rows) =>
					rows.every(
						(row, at) => rows.findIndex((r) => r.credential_id === row.credential_id) === at,
					),
				),
			continued: z
				.object({
					stage: z.literal("rename"),
					seq: z.number().int().min(1).max(16),
					body_hash: bytes32,
				})
				.strict()
				.optional(),
			...times,
		})
		.strict(),
	keyChange: z
		.object({
			v,
			iss: id,
			purpose: z.enum(["first-key", purposes.passkeyAdd, purposes.passkeyManage]),
			change: z.discriminatedUnion("op", [
				z.object({ op: z.literal("add"), credential_id: id, key_jkt: thumbprint }).strict(),
				z.object({ op: z.literal("delete"), credential_id: id }).strict(),
			]),
			receipt: compactJws.optional(),
			status: compactJws.optional(),
			stateOf: compactJws.optional(),
			...times,
		})
		.strict()
		.refine((c) => (c.change.op === "add") === (c.purpose !== purposes.passkeyManage)),
});
const sealedValue = z
	.object({
		enc: z.string().regex(/^B[A-P][A-Za-z0-9_-]{84}[AEIMQUYcgkosw048]$/),
		ct: z.string().min(22).refine(canonical),
	})
	.strict();

/** The bodies' schemas: what each reader opened or verified, and the answers the Front carries unread (`answers`). */
export const payloads = Object.freeze({
	statement,
	completion,
	creation,
	possession,
	passkeyAdd: management(purposes.passkeyAdd),
	passkeyManage: management(purposes.passkeyManage),
	startPlain,
	mailPlain,
	codePlain,
	completions,
	answers: Object.freeze({
		authorization: authorizationAnswer,
		statement: z.object({ statement: compactJws }).strict(),
		sealed: z.object({ sealed: sealedValue }).strict(),
		nonce: z.object({ nonce: bytes32 }).strict(),
	}),
});

export type StatementPayload = z.infer<typeof statement>;
export type CompletionPayload = z.infer<typeof completion>;
export type CreationPayload = z.infer<typeof creation>;
export type PossessionPayload = z.infer<typeof possession>;
export type AuthorizationAnswer = z.infer<typeof authorizationAnswer>;
export type AuthorizationItems = z.infer<typeof approval>;
export type SigningKey = z.infer<typeof signingKey>;

/** A canonical JSON text: object keys sorted, undefined members left out, so both sides build the same bytes. */
export function canonicalText(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalText).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalText(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

/**
 * What a passkey's thumbprint (RFC 7638; RFC 8037 for an OKP key) is the SHA-256 of: the JWK's
 * required members, sorted, with no space. A JWK that is not a passkey's as `PasskeyJwk` holds it
 * (another member, another spelling of the same bytes, a value out of its bounds) has none.
 */
export function keyThumbprintInput(jwk: unknown): string | undefined {
	const read = passkeyJwk.safeParse(jwk);
	return read.success ? canonicalText(read.data) : undefined;
}

/**
 * The items T approves, from a JAR's payload and its hash, by the one rule both sides run and compare
 * exactly: an error names the claim that is unknown or missing, or the value that is not allowed.
 */
export function itemsFromJar(
	payload: Readonly<Record<string, unknown>>,
	jarHash: string,
): { readonly items: AuthorizationItems } | { readonly error: string } {
	const allowed: readonly string[] = [...authorizationItems, ...jarEnvelope];
	for (const key of Object.keys(payload))
		if (!allowed.includes(key)) return { error: `unknown_item:${key}` };
	for (const key of requiredItems) {
		if (typeof payload[key] !== "string" || payload[key] === "")
			return { error: `missing_item:${key}` };
	}
	const items: Record<string, unknown> = { jar_hash: jarHash };
	for (const key of authorizationItems) if (payload[key] !== undefined) items[key] = payload[key];
	const read = approval.safeParse(items);
	return read.success
		? { items: read.data }
		: { error: `item:${String(read.error.issues[0]?.path[0])}` };
}

/** What a WebAuthn challenge is the hash of: the use and the statement's compact bytes. */
export const challengeInput = (statement: string, use: "get" | "create") =>
	`${use}\u0000${statement}`;

/**
 * The first key's words and inputs: its stages; what its evidence value is the hash of (the mail's
 * token); and the additional data a sealed request is bound to (its stage, nonce and the screen's
 * keys, so a swapped key fails to open); and what a recovery signs with E_sig, where the creation's
 * answer was lost (§C.4): the mail's nonce and the SHA-256 of the sealed request's `enc` then `ct`.
 */
export const firstKey = Object.freeze({
	stages: firstKeyStages,
	evidenceInput: (token: string) => `first-key-token\u0000${token}`,
	aad: (stage: FirstKeyStage, nonce: string, eEnc: string, eSig: SigningKey) =>
		canonicalText({
			purpose: `first-key/${stage}`,
			nonce,
			e_enc: eEnc,
			e_sig: { x: eSig.x, y: eSig.y },
		}),
	recoverInput: (nonce: string, digest: string) =>
		canonicalText({ purpose: "first-key/recover", nonce, digest }),
});

const continuationStages = Object.freeze(["register", "delete", "rename"] as const);
export type ContinuationStage = (typeof continuationStages)[number];

/**
 * A statement's continuation (§C.2, §C.6): its stages; what E_sig signs for one (`of`: the
 * statement's hash, the stage, the sequence and the body's hash, the same bytes for `register` as
 * before the stages were named); how it signs (`signature`: ES256's raw r||s over `of`'s UTF-8); and
 * the bodies of a delete and a rename, whose canonical text's SHA-256 is the body's hash.
 */
export const continuation = Object.freeze({
	stages: continuationStages,
	of: (stage: ContinuationStage, statementHash: string, seq: number, bodyHash: string) =>
		canonicalText({ h: statementHash, stage, seq, body: bodyHash }),
	signature: Object.freeze({
		alg: "ES256",
		form: "r||s",
		over: "UTF-8 of continuation.of",
	} as const),
	bodies: Object.freeze({
		delete: z.object({ credential_id: id }).strict(),
		rename: z.object({ credential_id: id, label }).strict(),
	}),
});
