import { canonicalText, itemsFromJar, type StatementPayload } from "@mod/sdk-core-wire";
import { schemas as logSchemas, logTyps, type RecordRef } from "@mod/transparency-wire";
import { base64url, deepFreeze, digest, fromBase64url, textOf, utf8 } from "./bytes.ts";
import { challengeOf } from "./challenge.ts";
import { type CompletionError, type CompletionOptions, readCompletion } from "./completion.ts";
import type { Sealed } from "./hpke.ts";
import { type Jwk, keyIdentity } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";
import { readApprovalReceipt } from "./receipt.ts";
import { readStatement, type StatementError, type StatementOptions } from "./statement.ts";

/** The claims of a JAR's payload, read without its signature (the Core verifies that), or none. */
function jarClaims(jar: string): Record<string, unknown> | undefined {
	const parts = jar.split(".");
	const bytes = parts.length === 3 ? fromBase64url(parts[1] ?? "") : undefined;
	const text = bytes && textOf(bytes);
	if (text === undefined) return undefined;
	try {
		const value: unknown = JSON.parse(text);
		return value !== null && typeof value === "object" && !Array.isArray(value)
			? (value as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}

/** Why T is not shown: a statement's refusal, the JAR the screen holds, or items that differ from it. */
export type AuthorizationError = StatementError | "jar" | "items";

/** Why a pushed T is not shown: a statement's refusal, or a client or `request_uri` other than the URL names. */
export type PushedAuthorizationError = StatementError | "client" | "request_uri";

/** T as `read` or `readPushed` gave it: the statement and its compact bytes. Only those two make one. */
export interface ReadT {
	readonly statement: StatementPayload;
	readonly compact: string;
}
const issued = new WeakSet<ReadT>();

/** Whether `read` or `readPushed` gave this T. Not offered: for this package's sign-up path. */
export const wasRead = (t: ReadT): boolean => issued.has(t);

/**
 * T read before it is shown (§3.4 ③): the statement, and its items exactly the items the JAR the
 * screen holds gives by sdk-core-wire's one rule, its hash included.
 */
async function read(
	statement: string,
	jar: string,
	options: Omit<StatementOptions<"authorization">, "purpose">,
): Promise<{ readonly t: ReadT } | { readonly error: AuthorizationError }> {
	const read = await readStatement(statement, { ...options, purpose: "authorization" });
	if ("error" in read) return read;
	const claims = jarClaims(jar);
	const items = claims && itemsFromJar(claims, await digest(jar));
	if (!items || "error" in items) return { error: "jar" };
	if (canonicalText(read.statement.approval) !== canonicalText(items.items))
		return { error: "items" };
	const t: ReadT = deepFreeze({ statement: read.statement, compact: read.compact });
	issued.add(t);
	return { t };
}

/**
 * T read before it is shown under PAR (§3.3), where the screen holds no JAR: the statement, signed by
 * the Core over the items and the hash of the JAR it was pushed, and its client and `request_uri` the
 * ones the URL names. The JAR's hash is not checked, as the screen holds no JAR; another request of
 * the same client given at the URL is the relying party's to refuse, by its state (R3).
 */
async function readPushed(
	statement: string,
	url: { readonly clientId: string; readonly requestUri: string },
	options: Omit<StatementOptions<"authorization">, "purpose">,
): Promise<{ readonly t: ReadT } | { readonly error: PushedAuthorizationError }> {
	const read = await readStatement(statement, { ...options, purpose: "authorization" });
	if ("error" in read) return read;
	const { approval } = read.statement;
	if (typeof url.clientId !== "string" || approval.client_id !== url.clientId)
		return { error: "client" };
	if (typeof url.requestUri !== "string" || approval.request_uri !== url.requestUri)
		return { error: "request_uri" };
	const t: ReadT = deepFreeze({ statement: read.statement, compact: read.compact });
	issued.add(t);
	return { t };
}

/**
 * What a `navigator.credentials.get` is asked for T `read` or `readPushed` gave: its get challenge, user
 * verification required, and the credentials where the caller names some. Credentials given empty,
 * or any one not a credential id, are refused: dropping them would ask for any credential.
 */
async function assertionOptions(
	t: ReadT,
	options: { readonly rpId: string; readonly credentials?: readonly string[] },
): Promise<
	| { readonly options: PublicKeyCredentialRequestOptions }
	| { readonly error: "statement" | "credentials" }
> {
	if (!issued.has(t)) return { error: "statement" };
	let allowCredentials: PublicKeyCredentialDescriptor[] | undefined;
	if (options.credentials !== undefined) {
		const given = options.credentials;
		if (given.length === 0) return { error: "credentials" };
		allowCredentials = [];
		// Every index, a hole too: a hole read as nothing must refuse, never shorten the list.
		for (let i = 0; i < given.length; i++) {
			const id = given[i];
			const bytes = typeof id === "string" && id !== "" ? fromBase64url(id) : undefined;
			if (!bytes || bytes.length === 0) return { error: "credentials" };
			allowCredentials.push({ type: "public-key", id: bytes });
		}
	}
	return {
		options: {
			challenge: await challengeOf(t.compact, "get"),
			rpId: options.rpId,
			userVerification: "required",
			...(allowCredentials ? { allowCredentials } : {}),
		},
	};
}

/** A completion as `finish` took it: its code, and ⑤'s record at `log`. Only `finish` makes one, for the T it was given. */
export interface Finished {
	readonly code: string;
	/** ⑤'s record, from its receipt: none at `L0`, where no receipt is read. */
	readonly approval?: RecordRef;
}

/**
 * How far the completion is checked, named by the caller (never a log key list left out): `L0` (a
 * bundle that fixes no log keys, as 0.1.0's) reads the completion alone, no receipt checked; `log`
 * also takes it only with ⑤'s receipt, signed by the log keys given.
 */
export type FinishChecks =
	| { readonly level: "L0" }
	| { readonly level: "log"; readonly receipt: string; readonly log: readonly Jwk[] };
const finished = new WeakMap<Finished, ReadT>();

/** Why a completion is not taken: T not `read`'s or `readPushed`'s, its own refusal, a level not named or its inputs (`checks`), ring and log keys shared, or ⑤'s receipt that does not bind it. */
export type FinishError = CompletionError | "statement" | "keys" | "receipt" | "checks";

/**
 * The completion taken, at the level the caller names: at `L0`, read alone and bound to the T `read`
 * or `readPushed` gave and the assertion sent, answering the code to POST to the RP; at `log` (A35), only with ⑤'s
 * receipt, signed by the log, binding them and the code, and only where no key of the log's is one of
 * the Core ring's (a Core holding both would sign its own receipt), answering ⑤'s record too.
 */
async function finish(
	t: ReadT,
	sealed: Sealed,
	options: Omit<CompletionOptions, "statement"> & FinishChecks,
): Promise<Finished | { readonly error: FinishError }> {
	if (!issued.has(t)) return { error: "statement" };
	if (options.level !== "L0" && options.level !== "log") return { error: "checks" };
	// The log's inputs, given whole, as keyChanges.read takes them: a receipt and a key list not empty.
	if (
		options.level === "log" &&
		(typeof options.receipt !== "string" || !Array.isArray(options.log) || options.log.length === 0)
	)
		return { error: "checks" };
	// A key with no identity verifies nothing, so it shares nothing either.
	const ring = new Set(options.ring.map(keyIdentity).filter((id) => id !== undefined));
	if (options.level === "log" && options.log.some((key) => ring.has(keyIdentity(key) ?? "")))
		return { error: "keys" };
	const read = await readCompletion(sealed, { ...options, statement: t.compact });
	if ("error" in read) return read;
	const { code } = read.completion;
	if (options.level === "L0") {
		const done: Finished = deepFreeze({ code });
		finished.set(done, t);
		return done;
	}
	const bound = await readApprovalReceipt(options.receipt, options.log, {
		statement: t.compact,
		assertion: options.assertion,
		code,
	});
	if (!bound) return { error: "receipt" };
	const done: Finished = deepFreeze({ code, approval: { shard: bound.shard, n: bound.n } });
	finished.set(done, t);
	return done;
}

/**
 * The callback's proof (A38): what the screen adds to its POST to the RP, signed with E_sig as ES256
 * (raw r||s), its header carrying E_sig's public key: T's issuer, client and state, the code's whole
 * UTF-8 SHA-256, ⑤'s record as `finish` gave it, and the device's time in seconds, on which no
 * freshness rests. The code and record must be what `finish` gave for this T, and the keys the ones
 * T names.
 */
async function callbackProof(
	t: ReadT,
	done: Finished,
	keys: ScreenKeys,
	now: number,
): Promise<
	| { readonly proof: string }
	| { readonly error: "statement" | "finish" | "level" | "keys" | "proof" }
> {
	if (!issued.has(t)) return { error: "statement" };
	if (finished.get(done) !== t) return { error: "finish" };
	// The proof names ⑤'s record, which only a receipt gives: none for a finish at L0.
	if (!done.approval) return { error: "level" };
	if (!namesKeys(keys, t.statement.e_enc, t.statement.e_sig)) return { error: "keys" };
	const header = logSchemas.callbackHeader.safeParse({
		alg: "ES256",
		typ: logTyps.callback,
		jwk: keys.eSig,
	});
	const body = logSchemas.callbackProof.safeParse({
		iss: t.statement.iss,
		client_id: t.statement.approval.client_id,
		state: t.statement.approval.state,
		code_hash: await digest(done.code),
		apr: { shard: done.approval.shard, n: done.approval.n },
		iat: Math.floor(now / 1000),
	});
	if (!header.success || !body.success) return { error: "proof" };
	const input = `${base64url(utf8(JSON.stringify(header.data)))}.${base64url(utf8(JSON.stringify(body.data)))}`;
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keys.signing.privateKey,
		utf8(input),
	);
	return { proof: `${input}.${base64url(new Uint8Array(signature))}` };
}

/** An authorization's steps on the screen: read T against the JAR, or by the client and the `request_uri` under PAR, ask the passkey, take the completion, sign the callback's proof. */
export const authorization = Object.freeze({
	read,
	readPushed,
	assertionOptions,
	finish,
	callbackProof,
});
