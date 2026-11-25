import { type CompletionPayload, hpke, payloads, typs } from "@mod/sdk-core-wire";
import { digest, textOf, utf8 } from "./bytes.ts";
import { openSealed, type Sealed } from "./hpke.ts";
import { type Jwk, verifyCompact } from "./jws.ts";
import type { ScreenKeys } from "./keys.ts";

/** Why a completion is not read: it does not open, its signature, `typ`, shape, issuer, or the T or assertion it binds. */
export type CompletionError =
	| "open"
	| "signature"
	| "typ"
	| "payload"
	| "issuer"
	| "statement"
	| "assertion";

export interface CompletionOptions {
	readonly keys: ScreenKeys;
	readonly ring: readonly Jwk[];
	readonly issuer: string;
	/** The additional data the Core sealed the completion under. */
	readonly aad: Uint8Array;
	/** T's compact bytes, as the screen read it. */
	readonly statement: string;
	/** The assertion's bytes, as the screen sent them. */
	readonly assertion: Uint8Array;
}

/**
 * A completion's sealed answer opened: with the screen's encryption key under the completion's info
 * and the additional data given, unpadded where it was padded, signed by the Core's ring as a
 * completion (never a statement's `typ`). Its payload is the caller's to read by the schema its
 * request waits for. A padded one off a bucket's length is `open`, as one that does not open.
 */
export async function openCompletion(
	sealed: Sealed,
	options: {
		readonly keys: ScreenKeys;
		readonly ring: readonly Jwk[];
		readonly aad: Uint8Array;
		/** Padded to a bucket (a passkey-add's or passkey-manage's): read back only at a bucket's length. */
		readonly padded?: boolean;
	},
): Promise<{ readonly payload: unknown } | { readonly error: "open" | "signature" | "typ" }> {
	const opened = await openSealed(
		options.keys.encryption,
		sealed,
		utf8(hpke.info.completion),
		options.aad,
	);
	const text = opened && textOf(opened);
	const jws = text !== undefined && options.padded ? hpke.unpaddedCompletion(text) : text;
	if (jws === undefined) return { error: "open" };
	const verified = await verifyCompact(jws, options.ring);
	if (!verified) return { error: "signature" };
	if (verified.header.typ !== typs.completion) return { error: "typ" };
	return { payload: verified.payload };
}

/**
 * The completion's answer: opened and signed as `openCompletion` holds it, of its schema, and bound
 * to the T the screen approved and the assertion it sent. Its times, as a statement's, are the
 * Core's to hold.
 */
export async function readCompletion(
	sealed: Sealed,
	options: CompletionOptions,
): Promise<{ readonly completion: CompletionPayload } | { readonly error: CompletionError }> {
	const opened = await openCompletion(sealed, options);
	if ("error" in opened) return opened;
	const read = payloads.completion.safeParse(opened.payload);
	if (!read.success) return { error: "payload" };
	const completion = read.data;
	if (completion.iss !== options.issuer) return { error: "issuer" };
	if (completion.t_hash !== (await digest(options.statement))) return { error: "statement" };
	if (completion.assertion_hash !== (await digest(options.assertion)))
		return { error: "assertion" };
	return { completion };
}
