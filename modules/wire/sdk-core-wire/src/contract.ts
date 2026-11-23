import { z } from "zod";

/**
 * The contract between the login screen and the Core, which the Core holds and the screen follows;
 * the Front relays it unread. It holds the words, the payloads' schemas and the inputs a hash or a
 * signature covers; hashing, signing and sealing are each side's own.
 */

/** The `typ` of each signed object. */
export const typs = Object.freeze({
	jar: "oauth-authz-req+jwt",
	/** The statement T a login approves, signed by the Core's ring. */
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
/** A JAR's envelope: claims that are no item, so T holds none of them. */
const jarEnvelope = Object.freeze(["iss", "aud", "iat", "nbf", "exp", "jti"] as const);

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

/** The fields every statement carries: its issuer, id, issue and expiry times, and the screen's two keys. */
const common = {
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
		iss: z.string().min(1),
		/** T's SHA-256. */
		t_hash: z.string().min(1),
		/** The assertion's bytes' SHA-256. */
		assertion_hash: z.string().min(1),
		code: z.string().min(1),
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
				/** The evidence's value the screen computes for itself: the mail token's hash on the first key's path. */
				evidence: z.string().min(1),
				/** The sealed mail request's ciphertext hash, as the Core opened it. */
				ct_hash: z.string().min(1),
				subject: z.string().min(1),
				options: z
					.object({
						user_id: z.string().min(1),
						rp_id: z.string().min(1),
						exclude_credentials: z.array(z.string()),
					})
					.strict(),
			})
			.strict(),
	})
	.strict();

/** A statement of the new key's possession: what the key's first `get()` proves. */
const possession = z
	.object({
		...common,
		nonce: z.string().min(1),
		purpose: z.literal(purposes.possession),
		possession: z
			.object({
				creation_hash: z.string().min(1),
				key_hash: z.string().min(1),
				credential_id: z.string().min(1),
				reservation_id: z.string().min(1),
			})
			.strict(),
	})
	.strict();

/** The first key's stages, each with a nonce of its own. */
export const firstKeyStages = Object.freeze(["start", "mail"] as const);
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

/** The payloads' schemas, as each reader holds what it opened or verified to them. */
export const payloads = Object.freeze({
	statement,
	completion,
	creation,
	possession,
	startPlain,
	mailPlain,
	codePlain,
});

export type StatementPayload = z.infer<typeof statement>;
export type CompletionPayload = z.infer<typeof completion>;
export type CreationPayload = z.infer<typeof creation>;
export type PossessionPayload = z.infer<typeof possession>;
export type AuthorizationItems = z.infer<typeof approval>;
export type SigningKey = z.infer<typeof signingKey>;

/** A canonical JSON text: object keys sorted, undefined members left out, so both sides build the same bytes. */
export function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
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

/** What the first key's evidence value is the hash of: the mail's token. */
export const evidenceInput = (token: string) => `first-key-token\u0000${token}`;

/** The additional data a first key's sealed request is bound to: its stage, nonce and the screen's keys, so a swapped key fails to open. */
export const firstKeyAad = (stage: FirstKeyStage, nonce: string, eEnc: string, eSig: SigningKey) =>
	canonicalJson({
		purpose: `first-key/${stage}`,
		nonce,
		e_enc: eEnc,
		e_sig: { x: eSig.x, y: eSig.y },
	});

/** What a registration's continuation signs: the statement's hash, the stage, the sequence and the response's hash. */
export const continuationInput = (statementHash: string, seq: number, responseHash: string) =>
	canonicalJson({ h: statementHash, stage: "register", seq, body: responseHash });
