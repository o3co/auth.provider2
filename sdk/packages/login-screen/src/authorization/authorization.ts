import { canonicalText, itemsFromJar, type StatementPayload } from "@mod/sdk-core-wire";
import { schemas as logSchemas, logTyps, type RecordRef } from "@mod/transparency-wire";
import { base64url, deepFreeze, digest, fromBase64url, textOf, utf8 } from "../bytes.ts";
import { challengeOf } from "../challenge.ts";
import { type CompletionError, type CompletionOptions, readCompletion } from "../completion.ts";
import type { Sealed } from "../hpke.ts";
import { type Jwk, keyIdentity } from "../jws.ts";
import { namesKeys, type ScreenKeys } from "../keys.ts";
import { readApprovalReceipt } from "../receipt.ts";
import { readStatement, type StatementError, type StatementOptions } from "../statement.ts";

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
/** The T ended with no code, by the person's denial or the Core's refusal carried: none is approved or continued after. */
const denied = new WeakSet<ReadT>();
/** Each ended T's end, and who ended it: one end per T. */
const ends = new WeakMap<ReadT, { readonly end: Refused; readonly by: "person" | "core" }>();
/** The T a completion was taken for: none is denied after. */
const completed = new WeakSet<ReadT>();

/** Whether `read` or `readPushed` gave this T. Not offered: for this package's sign-up path. */
export const wasRead = (t: ReadT): boolean => issued.has(t);

/** Whether this T was denied, so no step continues it. Not offered: for this package's sign-up path. */
export const wasDenied = (t: ReadT): boolean => denied.has(t);

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
	| { readonly error: "statement" | "credentials" | "denied" }
> {
	if (!issued.has(t)) return { error: "statement" };
	if (denied.has(t)) return { error: "denied" };
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

/** Why a completion is not taken: T not `read`'s or `readPushed`'s, or denied, its own refusal, a level not named or its inputs (`checks`), ring and log keys shared, or ⑤'s receipt that does not bind it. */
export type FinishError = CompletionError | "statement" | "denied" | "keys" | "receipt" | "checks";

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
	if (denied.has(t)) return { error: "denied" };
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
	// A denial given while the completion was being opened ends the attempt: no code is taken after it.
	if (options.level === "L0") {
		if (denied.has(t)) return { error: "denied" };
		const done: Finished = deepFreeze({ code });
		finished.set(done, t);
		completed.add(t);
		return done;
	}
	const bound = await readApprovalReceipt(options.receipt, options.log, {
		statement: t.compact,
		assertion: options.assertion,
		code,
	});
	if (!bound) return { error: "receipt" };
	if (denied.has(t)) return { error: "denied" };
	const done: Finished = deepFreeze({ code, approval: { shard: bound.shard, n: bound.n } });
	finished.set(done, t);
	completed.add(t);
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
	| { readonly error: "statement" | "denied" | "finish" | "level" | "keys" | "proof" }
> {
	if (!issued.has(t)) return { error: "statement" };
	if (denied.has(t)) return { error: "denied" };
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

/**
 * What the page POSTs, by `form_post`, to the relying party when the person refuses on the screen:
 * `error=access_denied`, T's `state` and T's issuer (RFC 9207), to T's `redirect_uri`. Every value is
 * T's, the Core's signed word, never the URL's.
 */
export interface Denial {
	readonly redirectUri: string;
	readonly fields: {
		readonly error: "access_denied";
		readonly state: string;
		readonly iss: string;
	};
}

/** What the page POSTs, as a denial, when the Core refused the finish: `error` the Core's word. */
export interface Refused {
	readonly redirectUri: string;
	readonly fields: {
		readonly error: CarriedRefusal;
		readonly state: string;
		readonly iss: string;
	};
}

/**
 * The Core's refusals of the finish that are the authorization's own answer (RFC 6749 §4.1.2.1, OIDC
 * Core §3.1.2.6), carried to the relying party: the login not approved or not of the subject or acr
 * asked, another subject than the hint's, the code grant, the scope or the resource no longer the
 * client's (`invalid_target`, RFC 8707 §2). Not the
 * screen's own request's (`invalid_request`), the moment's (`temporarily_unavailable`, `rate_limited`,
 * `server_error`), nor an unknown client's (RFC 6749 §4.1.2.1 sends that nowhere).
 */
const carried = [
	"access_denied",
	"login_required",
	"unauthorized_client",
	"invalid_scope",
	"invalid_target",
] as const;
export type CarriedRefusal = (typeof carried)[number];

/** The end of T with `error`: denied, the same end answered for it however asked again. */
function ended(
	t: ReadT,
	error: CarriedRefusal,
	by: "person" | "core",
): { readonly end: Refused; readonly by: "person" | "core" } | { readonly error: "finished" } {
	if (completed.has(t)) return { error: "finished" };
	const kept = ends.get(t);
	if (kept) return kept;
	denied.add(t);
	const { approval, iss } = t.statement;
	const end: Refused = deepFreeze({
		redirectUri: approval.redirect_uri,
		fields: { error, state: approval.state, iss },
	});
	const made = { end, by };
	ends.set(t, made);
	return made;
}

/**
 * The denial of T `read` or `readPushed` gave (RFC 6749 §4.1.2.1): it ends this attempt, so T is
 * approved, proved or continued to a sign-up by no later step. It revokes nothing already sent: an
 * approval in flight is still the Core's to judge until T's expiry. A T whose completion `finish`
 * took is not denied (`finished`): its code is the page's to POST. No callback proof goes with a
 * denial, as there is no code to bind. Asked again for the same T, it answers the same; for a T the
 * Core's refusal ended (`refusal`), `ended`: its POST was made, none goes beside it.
 */
function denial(t: ReadT): Denial | { readonly error: "statement" | "finished" | "ended" } {
	if (!issued.has(t)) return { error: "statement" };
	const made = ended(t, "access_denied", "person");
	if ("error" in made) return made;
	// The person's own end is access_denied's alone; one the Core's refusal made is no denial to POST again.
	return made.by === "person" ? (made.end as Denial) : { error: "ended" };
}

/**
 * The Core's refusal of the finish, by its `error` as the page read it (front-core-wire's `refusals`),
 * carried to the relying party as a denial is, and ending T alike: one of `CarriedRefusal`. Any other
 * is `refusal`, T not ended: the screen shows its own page. The page asks it once it gives the attempt
 * up: a refused approval the person may try again (another key) is not yet the attempt's end. The word
 * is unauthenticated: a Front may make one up, even in place of a completion it holds, ending T (no
 * code then); the relying party fails the attempt on it and acts on it no further.
 */
function refusal(
	t: ReadT,
	error: string,
): Refused | { readonly error: "statement" | "finished" | "refusal" } {
	if (!issued.has(t)) return { error: "statement" };
	const word = carried.find((one) => one === error);
	if (word === undefined) return { error: "refusal" };
	const made = ended(t, word, "core");
	return "error" in made ? made : made.end;
}

/** An authorization's steps on the screen: read T against the JAR, or by the client and the `request_uri` under PAR, ask the passkey, take the completion, sign the callback's proof; or end it with no code, by the person's denial or the Core's refusal carried. */
export const authorization = Object.freeze({
	read,
	readPushed,
	assertionOptions,
	finish,
	callbackProof,
	denial,
	refusal,
});
