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

/**
 * The source the Front determined for the request (its address, as the Front's trusted proxies tell
 * it), the first field of every operation; of length 0 where the Front could not determine one. The
 * Front's declaration: the Core counts by it while the Front is honest.
 */
const source = field("source", "visible", 0, 45);

/** A sealed request of the first key's path: its nonce, the screen's keys, and the HPKE encapsulation and ciphertext only the Core opens. */
const sealed = Object.freeze([
	source,
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
			source,
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
			source,
			field("statement", "jws", 1, 4096),
			field("assertion", "utf8", 1, 8192),
		] as const),
	}),
	/** A code's exchange at the token endpoint. */
	token: Object.freeze({
		code: 0x03,
		fields: Object.freeze([
			source,
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
			source,
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
		fields: Object.freeze([source, field("stage", "enum", 1, 1, 2)] as const),
	}),
	/** The first key's start, sealed (inside: the identifier, and a password where the deployment asks one). */
	firstKeyStart: Object.freeze({ code: 0x06, fields: sealed }),
	/** The mail's side, sealed as the start is (inside: the token, the identifier and the code). */
	firstKeyMail: Object.freeze({ code: 0x07, fields: sealed }),
	/** A registration's continuation: the creation statement, its sequence, the registration response and the screen's signature (r||s). */
	firstKeyContinue: Object.freeze({
		code: 0x08,
		fields: Object.freeze([
			source,
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
			source,
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
		/** When to ask again, in whole seconds as decimal digits; of length 0 where none is said. */
		field("retryAfter", "visible", 0, 10),
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
	"rate_limited",
	"too_many_attempts",
] as const);

/** An enum field carried as text: the value each text gives, and the value any other text gives; without `other`, any other is refused. */
export interface EnumTexts {
	readonly texts: Readonly<Record<string, number>>;
	readonly other?: number;
}

/**
 * One operation as HTTP: a POST to `path`, its body a form or a JSON object. A field is carried in the
 * body under its own name, or the one `bodyNames` gives, or in the header `headerNames` gives; a
 * `bytes` field as base64url text without padding, an enum as `enumTexts` gives it or else as its
 * number in decimal, and any other as its text. An empty text is no value: a field of length 0 is not
 * sent. The `source` field is no part of the request: the Front fills it from the source it determined.
 */
export interface OverHttp {
	readonly path: string;
	readonly body: "form" | "json";
	/** Where operations share a path, the body's value that picks this one; it is sent with the request. */
	readonly discriminator?: { readonly name: string; readonly value: string };
	readonly bodyNames?: Readonly<Record<string, string>>;
	/** Header names, lower case. */
	readonly headerNames?: Readonly<Record<string, string>>;
	readonly enumTexts?: Readonly<Record<string, EnumTexts>>;
	/** The status the operation's success is answered with; without it, 200. */
	readonly successStatus?: number;
	/** Called by a page of another origin (the login screen): the request headers it sends beyond the safelisted ones. */
	readonly crossOrigin?: { readonly headers: readonly string[] };
}

const screen = (path: string, more: Partial<OverHttp> = {}): OverHttp =>
	Object.freeze({
		path,
		body: "json",
		crossOrigin: Object.freeze({ headers: Object.freeze(["content-type"]) }),
		...more,
	});

/** The token endpoint's names (RFC 6749 §4.1.3, §6; RFC 7521 §4.2; RFC 9396; RFC 9449). */
const tokenNames = Object.freeze({
	clientAssertionType: "client_assertion_type",
	clientAssertion: "client_assertion",
	clientId: "client_id",
	authorizationDetails: "authorization_details",
});
const tokenEnumTexts = Object.freeze({
	clientAssertionType: Object.freeze({
		texts: Object.freeze({ "urn:ietf:params:oauth:client-assertion-type:jwt-bearer": 1 }),
		other: 0,
	}),
	authorizationDetails: Object.freeze({ texts: Object.freeze({ "": 0 }), other: 1 }),
});
const dpopHeader = Object.freeze({ dpop: "dpop" });

/**
 * How each operation crosses the Front: the request the Front takes for it and the Core's route serves,
 * and the status each refusal is answered with, every other 400 (RFC 6749 §5.2); a refusal's
 * `retryAfter` is sent as `Retry-After`. An `ok` reply's body is the JSON the Core's route answered
 * with the operation's success status. An enum value no text names is sent as the text `other`.
 * `declaredSource` names the field every operation carries the Front's source in.
 */
export const overHttp = Object.freeze({
	declaredSource: "source" as const,
	operations: Object.freeze({
		loginStart: screen("/login/start"),
		loginFinish: screen("/login/finish"),
		token: Object.freeze({
			path: "/token",
			body: "form",
			bodyNames: Object.freeze({
				grantType: "grant_type",
				redirectUri: "redirect_uri",
				codeVerifier: "code_verifier",
				...tokenNames,
			}),
			headerNames: dpopHeader,
			enumTexts: Object.freeze({
				grantType: Object.freeze({ texts: Object.freeze({ authorization_code: 1 }), other: 0 }),
				...tokenEnumTexts,
			}),
		}),
		refresh: Object.freeze({
			path: "/token",
			body: "form",
			discriminator: Object.freeze({ name: "grant_type", value: "refresh_token" }),
			bodyNames: Object.freeze({ refreshToken: "refresh_token", ...tokenNames }),
			headerNames: dpopHeader,
			enumTexts: tokenEnumTexts,
		}),
		firstKeyNonce: screen("/first-key/nonce", {
			enumTexts: Object.freeze({
				stage: Object.freeze({ texts: Object.freeze({ start: 0, mail: 1 }) }),
			}),
		}),
		firstKeyStart: screen("/first-key/start"),
		firstKeyMail: screen("/first-key/mail"),
		firstKeyContinue: screen("/first-key/continue"),
		firstKeyFinish: screen("/first-key/finish"),
	} satisfies Record<keyof typeof requests, OverHttp>) as Readonly<
		Record<keyof typeof requests, OverHttp>
	>,
	statuses: Object.freeze({
		invalid_client: 401,
		temporarily_unavailable: 503,
		server_error: 500,
		rate_limited: 429,
		too_many_attempts: 429,
	}) as Readonly<Partial<Record<(typeof refusals)[number], number>>>,
});

export type RequestKind = keyof typeof requests;
export type Outcome = keyof typeof outcomes;
export type WireErrorName = keyof typeof wireErrors;
export type RefusalName = (typeof refusals)[number];
