import { contract } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";

export interface CodeFacts {
	readonly clientId: string;
	readonly redirectUri: string;
	readonly challenge: string;
	readonly nonce?: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session: string;
	readonly subject: string;
	/** The authentication context class the issuer judged met; carried to the token as it is. */
	readonly acr?: string;
	/** The reference of the record the code's chain roots in, its approval's: carried to the bundle unread. */
	readonly root: string;
	/** The binding the authorization asked for ahead (`dpop_jkt`): the code's tokens hold it, and none other. */
	readonly binding?: Binding;
}

export interface Codes {
	/**
	 * A code for the facts. Throws Unavailable where the store cannot tell, or the session is not
	 * entered at use (closed or short since the caller read it); TypeError for facts the session or
	 * the client contradict.
	 */
	issue(facts: CodeFacts): Promise<string>;
	/** A code's digest, its SHA-256 in base64url: what a record names it by, never the code itself. */
	digestOf(code: string): string;
	/** How long a code lives once issued, as `code-lifetime` says. */
	lifetimeMs(): number;
}

export const codes = contract<Codes>("code-grant");

/** The grant's type (RFC 6749 §4.1.3). */
export const codeGrantType = "authorization_code";

/** RFC 7636: an S256 challenge is 43 base64url characters; a code is issued only for one of this shape. */
export const challengeShape = /^[A-Za-z0-9_-]{43}$/;

export * from "./store.ts";
