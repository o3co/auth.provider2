/**
 * The Front to Core wire: a frame of fixed form, whose contract the Core holds. A frame is the
 * version (u8), a request's kind or a reply's outcome (u8), an id (u32 BE), the body's length
 * (u32 BE) and the body: each field of its kind in a fixed order, as its length (u16 BE) and bytes.
 * A structured value (a JAR, an assertion, a DPoP proof) travels as bytes the wire never reads.
 */

/** What a field's bytes may hold: its length and its characters, never what they mean. */
export type FieldType = "bytes" | "utf8" | "visible" | "b64url" | "jws" | "enum";

/** One field: its name, its type, its least and greatest length in bytes, and for an enum the count of its values. */
export interface FieldSpec {
	readonly name: string;
	readonly type: FieldType;
	readonly min: number;
	readonly max: number;
	readonly values?: number;
}

const field = <N extends string, T extends FieldType>(
	name: N,
	type: T,
	min: number,
	max: number,
	values?: number,
) =>
	Object.freeze(values === undefined ? { name, type, min, max } : { name, type, min, max, values });

/** The wire's version, the first byte of every frame. */
export const version = 1;
/** A frame's header: version, kind or outcome, id and the body's length. */
export const headerLength = 10;
/** The greatest request body; every kind's fields at their greatest fit within it. */
export const maxRequestBody = 24 * 1024;
/** The greatest reply body. */
export const maxReplyBody = 64 * 1024;

/** A sealed request of the first key's path: its nonce, the screen's keys, and the HPKE encapsulation and ciphertext only the Core opens. */
const sealed = Object.freeze([
	field("nonce", "b64url", 43, 43),
	field("eEnc", "bytes", 65, 65),
	field("eSigX", "bytes", 32, 32),
	field("eSigY", "bytes", 32, 32),
	field("enc", "bytes", 65, 65),
	field("ct", "bytes", 17, 2048),
] as const);

/** Each operation the Core opens to the Front, its code and its fields in order. A length of 0 is "not sent". */
export const requests = Object.freeze({
	/** The login's start: the client, its JAR, and the screen's encryption key (raw P-256, 65 bytes) and signing key (x and y). */
	loginStart: Object.freeze({
		code: 0x01,
		fields: Object.freeze([
			field("clientId", "visible", 1, 64),
			field("request", "jws", 1, 8192),
			field("eEnc", "bytes", 65, 65),
			field("eSigX", "bytes", 32, 32),
			field("eSigY", "bytes", 32, 32),
		] as const),
	}),
	/** The login's finish: the statement T and the assertion (the bytes the assertion's hash covers). */
	loginFinish: Object.freeze({
		code: 0x02,
		fields: Object.freeze([
			field("statement", "jws", 1, 4096),
			field("assertion", "utf8", 1, 8192),
		] as const),
	}),
	/** A code's exchange at the token endpoint. */
	token: Object.freeze({
		code: 0x03,
		fields: Object.freeze([
			field("grantType", "enum", 1, 1, 2),
			field("code", "b64url", 1, 128),
			field("redirectUri", "visible", 1, 512),
			field("codeVerifier", "visible", 43, 128),
			field("clientAssertionType", "enum", 1, 1, 2),
			field("clientAssertion", "jws", 1, 4096),
			field("clientId", "visible", 0, 64),
			field("authorizationDetails", "enum", 1, 1, 2),
			field("dpop", "jws", 0, 4096),
		] as const),
	}),
	/** A refresh (`grant_type=refresh_token`); a scope of length 0 was not sent. */
	refresh: Object.freeze({
		code: 0x04,
		fields: Object.freeze([
			field("refreshToken", "b64url", 1, 128),
			field("scope", "utf8", 0, 512),
			field("clientAssertionType", "enum", 1, 1, 2),
			field("clientAssertion", "jws", 1, 4096),
			field("clientId", "visible", 0, 64),
			field("authorizationDetails", "enum", 1, 1, 2),
			field("dpop", "jws", 0, 4096),
		] as const),
	}),
	/** A nonce of the first key's path: stage 0 for its start, 1 for the mail's side. */
	firstKeyNonce: Object.freeze({
		code: 0x05,
		fields: Object.freeze([field("stage", "enum", 1, 1, 2)] as const),
	}),
	/** The first key's start, sealed (inside: the identifier, and a password where the deployment asks one). */
	firstKeyStart: Object.freeze({ code: 0x06, fields: sealed }),
	/** The mail's side, sealed as the start is (inside: the token, the identifier and the code). */
	firstKeyMail: Object.freeze({ code: 0x07, fields: sealed }),
	/** A registration's continuation: the creation statement, its sequence, the registration response and the screen's signature (r||s). */
	firstKeyContinue: Object.freeze({
		code: 0x08,
		fields: Object.freeze([
			field("statement", "jws", 1, 4096),
			field("seq", "enum", 1, 1, 16),
			field("response", "utf8", 1, 8192),
			field("sig", "bytes", 64, 64),
		] as const),
	}),
	/** The first key's finish: the possession statement and the new key's assertion. */
	firstKeyFinish: Object.freeze({
		code: 0x09,
		fields: Object.freeze([
			field("statement", "jws", 1, 4096),
			field("assertion", "utf8", 1, 8192),
		] as const),
	}),
});

/** The values of the token request's enums. */
export const grant = Object.freeze({ other: 0, authorizationCode: 1 });
export const clientAssertionType = Object.freeze({ other: 0, jwtBearer: 1 });

/** The fixed code the Core answers a request it rejects with; no piece of the input goes back. */
export const wireErrors = Object.freeze({
	version: 1,
	kind: 2,
	length: 3,
	truncated: 4,
	fieldLength: 5,
	fieldSyntax: 6,
	trailing: 7,
	enumRange: 8,
});

/** A reply's outcome, its second byte. */
export const outcomes = Object.freeze({ ok: 0, refused: 1, rejected: 2 });

/** Each outcome's fields: `ok` carries the body the Core made, which the Front answers as it is. */
export const replies = Object.freeze({
	ok: Object.freeze([
		field("body", "bytes", 0, maxReplyBody - 2 - 2 - 64),
		field("dpopNonce", "b64url", 0, 64),
	] as const),
	refused: Object.freeze([
		field("error", "enum", 1, 1, 255),
		field("detail", "utf8", 0, 400),
		field("dpopNonce", "b64url", 0, 64),
	] as const),
	rejected: Object.freeze([field("code", "enum", 1, 1, 255)] as const),
});

/** The OAuth errors a refusal names; a refusal's `error` is a word's place plus one. */
export const refusals = Object.freeze([
	"invalid_request",
	"invalid_request_object",
	"invalid_client",
	"invalid_grant",
	"invalid_scope",
	"unsupported_grant_type",
	"access_denied",
	"invalid_dpop_proof",
	"use_dpop_nonce",
	"temporarily_unavailable",
	"server_error",
] as const);

export type RequestKind = keyof typeof requests;
export type Outcome = keyof typeof outcomes;
export type WireErrorName = keyof typeof wireErrors;
export type RefusalName = (typeof refusals)[number];
