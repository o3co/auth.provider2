import {
	type CreationPayload,
	continuation as continued,
	hpke,
	keyThumbprintInput,
	type PossessionPayload,
	payloads,
	firstKey as words,
} from "@mod/sdk-core-wire";
import { base64url, concat, deepFreeze, digest, fromBase64url, textOf, utf8 } from "./bytes.ts";
import { challengeOf } from "./challenge.ts";
import { openSealed, type Sealed, sealTo } from "./hpke.ts";
import type { Jwk } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";
import { readStatement, type StatementError } from "./statement.ts";

/** What the screen holds through the first key's path: the Core's ring and sealing key, its own keys, the issuer. */
export interface FirstKeyOptions {
	readonly ring: readonly Jwk[];
	/** The Core's sealing key, HPKE's raw P-256 point, as the screen's bundle fixes it. */
	readonly sealingKey: Uint8Array;
	readonly keys: ScreenKeys;
	readonly issuer: string;
}

const aadOf = (stage: "start" | "mail", nonce: string, keys: ScreenKeys) =>
	utf8(words.aad(stage, nonce, keys.eEnc, keys.eSig));
const json = (bytes: Uint8Array | undefined) => {
	const text = bytes && textOf(bytes);
	if (text === undefined) return undefined;
	try {
		return JSON.parse(text) as unknown;
	} catch {
		return undefined;
	}
};

/** The start: the identifier (and a password where the deployment asks one), sealed to the Core under the start's nonce and the screen's keys. */
async function start(
	plain: { readonly identifier: string; readonly password?: string },
	nonce: string,
	options: FirstKeyOptions,
): Promise<{ readonly sealed: Sealed } | { readonly error: "plain" }> {
	const read = payloads.startPlain.safeParse(plain);
	if (!read.success) return { error: "plain" };
	const sealed = await sealTo(
		options.sealingKey,
		utf8(hpke.info.firstKeyRequest),
		aadOf("start", nonce, options.keys),
		utf8(JSON.stringify(read.data)),
	);
	return { sealed };
}

/** The start's answer: the code, sealed to the screen under the code's info and the start's additional data. */
async function openCode(
	sealed: Sealed,
	nonce: string,
	options: Pick<FirstKeyOptions, "keys">,
): Promise<{ readonly code: string } | { readonly error: "open" | "payload" }> {
	const opened = await openSealed(
		options.keys.encryption,
		sealed,
		utf8(hpke.info.firstKeyCode),
		aadOf("start", nonce, options.keys),
	);
	const value = json(opened);
	if (value === undefined) return { error: "open" };
	const read = payloads.codePlain.safeParse(value);
	return read.success ? { code: read.data.code } : { error: "payload" };
}

/** The mail's side as the screen sealed it: the sealed request, its nonce, and what a creation must name of it. */
export interface Mail {
	readonly sealed: Sealed;
	/** The mail's nonce, the request was sealed under. */
	readonly nonce: string;
	/** The evidence's value: the mail token's hash. */
	readonly evidence: string;
	/** The ciphertext's hash: the SHA-256 of the sealed request's whole, its `enc` (65 bytes) then its `ct`. */
	readonly ctHash: string;
}
/** Each mail this page sealed, with the screen keys it was sealed under (a recovery signs with them). */
const mails = new WeakMap<Mail, ScreenKeys>();

/** The mail's side: the token (from the link's fragment), the identifier and the start's code, sealed to the Core. */
async function mail(
	plain: { readonly token: string; readonly identifier: string; readonly code: string },
	nonce: string,
	options: FirstKeyOptions,
): Promise<{ readonly mail: Mail } | { readonly error: "plain" }> {
	const read = payloads.mailPlain.safeParse(plain);
	if (!read.success) return { error: "plain" };
	const sealed = await sealTo(
		options.sealingKey,
		utf8(hpke.info.firstKeyRequest),
		aadOf("mail", nonce, options.keys),
		utf8(JSON.stringify(read.data)),
	);
	const sent: Mail = deepFreeze({
		sealed,
		nonce,
		evidence: await digest(words.evidenceInput(read.data.token)),
		ctHash: await digest(concat(sealed.enc, sealed.ct)),
	});
	mails.set(sent, options.keys);
	return { mail: sent };
}

/**
 * A recovery where the creation's answer was lost (§C.4): the mail's nonce, its sealed request's
 * digest (the ciphertext's hash a creation names), and E_sig's signature, ES256's raw r||s
 * (base64url), over sdk-core-wire's `firstKey.recoverInput`, signed with the keys the mail was
 * sealed under. The Core answers the creation it kept, the same bytes, read by `readCreation`. Only
 * a mail this page sealed is recovered: a reloaded page has lost it.
 */
async function recover(
	sent: Mail,
): Promise<
	| { readonly nonce: string; readonly digest: string; readonly sig: string }
	| { readonly error: "mail" }
> {
	const keys = mails.get(sent);
	if (keys === undefined) return { error: "mail" };
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keys.signing.privateKey,
		utf8(words.recoverInput(sent.nonce, sent.ctHash)),
	);
	return { nonce: sent.nonce, digest: sent.ctHash, sig: base64url(new Uint8Array(signature)) };
}

/** A creation as `readCreation` gave it. Only `readCreation` makes one. */
export interface ReadCreation {
	readonly statement: CreationPayload;
	readonly compact: string;
}
const creations = new WeakSet<ReadCreation>();

/**
 * A creation another path read (passkey-add's, `management.finish`), made a `ReadCreation` so the
 * same next steps take it. Not offered: only a reader that held the creation to its path makes one.
 */
export function creationOf(statement: CreationPayload, compact: string): ReadCreation {
	const creation: ReadCreation = deepFreeze({ statement, compact });
	creations.add(creation);
	return creation;
}

/**
 * The creation read before `create()`: a statement of its purpose, of the first key's path (no
 * `basis`, or `first-key`; §C.3), its evidence and ciphertext hash exactly the screen's own for the
 * mail it sealed. Another's would mean the Front rewrapped another token or request to the screen's
 * keys. The schema already holds `options.algorithms` to one or more, none twice.
 */
async function readCreation(
	compact: string,
	sent: Mail,
	options: FirstKeyOptions,
): Promise<
	| { readonly creation: ReadCreation }
	| { readonly error: StatementError | "mail" | "basis" | "evidence" | "ciphertext" }
> {
	if (!mails.has(sent)) return { error: "mail" };
	const read = await readStatement(compact, { ...options, purpose: "creation" });
	if ("error" in read) return read;
	const { basis } = read.statement.creation;
	if (basis !== undefined && basis !== "first-key") return { error: "basis" };
	if (read.statement.creation.evidence !== sent.evidence) return { error: "evidence" };
	if (read.statement.creation.ct_hash !== sent.ctHash) return { error: "ciphertext" };
	return { creation: creationOf(read.statement, compact) };
}

const credentialsOf = (ids: readonly string[]) => {
	const out: PublicKeyCredentialDescriptor[] = [];
	for (let i = 0; i < ids.length; i++) {
		const id = ids[i];
		const bytes = typeof id === "string" && id !== "" ? fromBase64url(id) : undefined;
		if (!bytes || bytes.length === 0) return undefined;
		out.push({ type: "public-key", id: bytes });
	}
	return out;
};

/** What a `navigator.credentials.create` is asked for a creation: its create challenge, its subject and options, a resident key of an algorithm the creation offers, in its order, user verification. */
async function createOptions(
	creation: ReadCreation,
	options: { readonly rpName: string },
): Promise<
	| { readonly options: PublicKeyCredentialCreationOptions }
	| { readonly error: "statement" | "options" }
> {
	if (!creations.has(creation)) return { error: "statement" };
	const { account, options: asked } = creation.statement.creation;
	const userId = fromBase64url(asked.user_id);
	const exclude = credentialsOf(asked.exclude_credentials);
	// WebAuthn's user handle is 1 to 64 bytes.
	if (!userId || userId.length === 0 || userId.length > 64 || !exclude) return { error: "options" };
	return {
		options: {
			challenge: await challengeOf(creation.compact, "create"),
			rp: { id: asked.rp_id, name: options.rpName },
			user: { id: userId, name: account, displayName: account },
			pubKeyCredParams: asked.algorithms.map((alg) => ({ type: "public-key" as const, alg })),
			excludeCredentials: exclude,
			authenticatorSelection: { residentKey: "required", userVerification: "required" },
			attestation: "none",
		},
	};
}

/**
 * A continuation of the register stage, signed with E_sig as ES256's raw r||s (64 bytes, base64url)
 * over sdk-core-wire's input: the creation's hash, the sequence and the response's hash. The keys
 * must be the ones the creation names; the sequence's upper bound is the Front's and the Core's.
 */
async function continuation(
	creation: ReadCreation,
	seq: number,
	response: string,
	keys: ScreenKeys,
): Promise<{ readonly signature: string } | { readonly error: "statement" | "keys" | "sequence" }> {
	if (!creations.has(creation)) return { error: "statement" };
	const { e_enc, e_sig } = creation.statement;
	if (!namesKeys(keys, e_enc, e_sig)) return { error: "keys" };
	if (!Number.isSafeInteger(seq) || seq < 1) return { error: "sequence" };
	const input = continued.of(
		"register",
		await digest(creation.compact),
		seq,
		await digest(response),
	);
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keys.signing.privateKey,
		utf8(input),
	);
	return { signature: base64url(new Uint8Array(signature)) };
}

/**
 * For each algorithm a creation may offer (COSE's numbers): WebCrypto's parameters to read the new
 * key's SPKI by, and the members its thumbprint is of (RFC 7638 §3.2, RFC 8037 §2).
 */
const newKeyForms: Readonly<
	Record<
		number,
		{
			readonly params: Algorithm | EcKeyImportParams | RsaHashedImportParams;
			readonly members: readonly (keyof JsonWebKey)[];
		}
	>
> = Object.freeze({
	[-7]: { params: { name: "ECDSA", namedCurve: "P-256" }, members: ["crv", "kty", "x", "y"] },
	[-8]: { params: { name: "Ed25519" }, members: ["crv", "kty", "x"] },
	[-257]: { params: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, members: ["e", "kty", "n"] },
});

/**
 * The new key's thumbprint, from the SPKI `getPublicKey()` gave (an `ArrayBuffer`, or bytes) and the
 * algorithm `getPublicKeyAlgorithm()` gave: the SPKI read as a key of that algorithm, in its one DER
 * form (it writes back to the same bytes), its members passed by sdk-core-wire's one rule. None for
 * an algorithm not offered, a SPKI that is not such a key or not in that form, or a key the protocol
 * does not take.
 */
async function thumbprintOf(
	given: ArrayBuffer | Uint8Array,
	alg: number,
): Promise<string | undefined> {
	const form = Object.hasOwn(newKeyForms, alg) ? newKeyForms[alg] : undefined;
	if (!form) return undefined;
	// One copy, read for the import and the comparison alike, whatever the caller does meanwhile.
	const spki = given instanceof Uint8Array ? given.slice() : new Uint8Array(given.slice(0));
	let jwk: JsonWebKey;
	try {
		const key = await crypto.subtle.importKey("spki", spki, form.params, true, ["verify"]);
		const again = new Uint8Array(await crypto.subtle.exportKey("spki", key));
		if (again.length !== spki.length || again.some((byte, i) => byte !== spki[i])) return undefined;
		jwk = await crypto.subtle.exportKey("jwk", key);
	} catch {
		return undefined;
	}
	const input = keyThumbprintInput(
		Object.fromEntries(form.members.map((name) => [name, jwk[name]])),
	);
	return input === undefined ? undefined : digest(input);
}

/** A possession as `readPossession` gave it. Only `readPossession` makes one. */
export interface ReadPossession {
	readonly statement: PossessionPayload;
	readonly compact: string;
	/** The RP id the creation named, which the new key's `get()` is asked for. */
	readonly rpId: string;
}
const possessions = new WeakSet<ReadPossession>();

/**
 * The possession read before the new key's `get()`: a statement of its purpose naming this creation,
 * the key the screen's own `create()` made (of an algorithm the creation offered, by its JWK
 * thumbprint) and that credential.
 */
async function readPossession(
	compact: string,
	creation: ReadCreation,
	credential: {
		readonly id: string;
		readonly spki: ArrayBuffer | Uint8Array;
		readonly alg: number;
	},
	options: Omit<FirstKeyOptions, "sealingKey">,
): Promise<
	| { readonly possession: ReadPossession }
	| { readonly error: StatementError | "statement" | "creation" | "key" | "credential" }
> {
	if (!creations.has(creation)) return { error: "statement" };
	const read = await readStatement(compact, { ...options, purpose: "possession" });
	if ("error" in read) return read;
	const { possession } = read.statement;
	if (possession.creation_hash !== (await digest(creation.compact))) return { error: "creation" };
	const offered: readonly number[] = creation.statement.creation.options.algorithms;
	const jkt = offered.includes(credential.alg)
		? await thumbprintOf(credential.spki, credential.alg)
		: undefined;
	if (jkt === undefined || possession.key_jkt !== jkt) return { error: "key" };
	if (possession.credential_id !== credential.id) return { error: "credential" };
	const held: ReadPossession = deepFreeze({
		statement: read.statement,
		compact,
		rpId: creation.statement.creation.options.rp_id,
	});
	possessions.add(held);
	return { possession: held };
}

/** What the new key's first `get()` is asked: the possession's get challenge, for its credential alone, at the creation's RP, user verification. */
async function assertionOptions(
	possession: ReadPossession,
): Promise<
	| { readonly options: PublicKeyCredentialRequestOptions }
	| { readonly error: "statement" | "credential" }
> {
	if (!possessions.has(possession)) return { error: "statement" };
	const allowCredentials = credentialsOf([possession.statement.possession.credential_id]);
	if (!allowCredentials) return { error: "credential" };
	return {
		options: {
			challenge: await challengeOf(possession.compact, "get"),
			rpId: possession.rpId,
			userVerification: "required",
			allowCredentials,
		},
	};
}

/** The first key's path on the screen: the start, the mail's side (and its recovery), the creation, `create()`, the continuation, the possession, the new key's `get()`. */
export const firstKey = Object.freeze({
	start,
	openCode,
	mail,
	recover,
	readCreation,
	createOptions,
	continuation,
	readPossession,
	assertionOptions,
});
