import { continuations } from "@mod/continuation-wire";
import { type ReadT, wasRead } from "./authorization.ts";
import { base64url, digest, utf8 } from "./bytes.ts";
import { creationOf, type ReadCreation } from "./first-key.ts";
import type { Jwk } from "./jws.ts";
import { namesKeys, type ScreenKeys } from "./keys.ts";
import { readStatement, type StatementError } from "./statement.ts";

/** What F1's continuation sends on `continue`: its stage and sequence, its body's text, and E_sig's signature. */
export interface SignUpContinuation {
	readonly stage: "sign-up";
	readonly seq: 1;
	/** The body's text, `{}`: the one spelling continuation-wire gives, which the Core takes alone. */
	readonly body: string;
	/** E_sig's signature, ES256's raw r||s, base64url. */
	readonly sig: string;
}

/**
 * F1's continuation of T (sign-up, the credential first; §3.13): asked where ②'s answer let a
 * passkey be made first, for the T `authorization.read` gave, signed with the keys T names over
 * continuation-wire's `of("sign-up", T's hash, 1, the body's hash)`. One per T (sequence 1 alone):
 * a resend, signed again or not, is answered with what the Core kept (the creation, or a final
 * refusal, after which the screen starts the authorization again; `pending` while the first runs).
 */
async function continuation(
	t: ReadT,
	keys: ScreenKeys,
): Promise<SignUpContinuation | { readonly error: "statement" | "keys" }> {
	if (!wasRead(t)) return { error: "statement" };
	if (!namesKeys(keys, t.statement.e_enc, t.statement.e_sig)) return { error: "keys" };
	const body = continuations.bodyText("sign-up", {}) ?? "{}";
	const input = continuations.of("sign-up", await digest(t.compact), 1, await digest(body));
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keys.signing.privateKey,
		utf8(input),
	);
	return { stage: "sign-up", seq: 1, body, sig: base64url(new Uint8Array(signature)) };
}

/**
 * F1's creation, the answer to its continuation: a creation statement naming this screen's keys, of
 * sign-up's basis (no ciphertext hash and no account, its name in `user_name`, as sdk-core-wire's
 * schema holds), its evidence the hash of the T the screen read. Read, it is a `ReadCreation` the
 * first key's next steps take (`createOptions`, `continuation`, `readPossession`).
 */
async function readCreation(
	compact: string,
	t: ReadT,
	options: { readonly ring: readonly Jwk[]; readonly keys: ScreenKeys; readonly issuer: string },
): Promise<
	| { readonly creation: ReadCreation }
	| { readonly error: StatementError | "statement" | "keys" | "basis" | "evidence" }
> {
	if (!wasRead(t)) return { error: "statement" };
	if (!namesKeys(options.keys, t.statement.e_enc, t.statement.e_sig)) return { error: "keys" };
	const read = await readStatement(compact, { ...options, purpose: "creation" });
	if ("error" in read) return read;
	if (read.statement.creation.basis !== "sign-up") return { error: "basis" };
	if (read.statement.creation.evidence !== (await digest(t.compact))) return { error: "evidence" };
	return { creation: creationOf(read.statement, read.compact) };
}

/** F1's path on the screen (sign-up, the credential first): T's continuation and its creation; the first key's steps after. */
export const signUp = Object.freeze({ continuation, readCreation });
