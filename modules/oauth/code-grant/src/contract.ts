import { contract, extensionPoint } from "@mod/kernel";
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

/** A redemption that issued its token, as a hook is told of it. */
export interface Redeemed {
	/** The redemption's name: the code's digest, as `digestOf` gives it to whoever issued the code. */
	readonly redemption: string;
	readonly subject: string;
	readonly scope: readonly string[];
	/** The access token issued: its id and its end (epoch ms). */
	readonly access: { readonly id: string; readonly expiresAt: number };
}

/** What runs with a redemption, from a module keeping something for the code's tokens. */
export interface RedemptionHook {
	readonly name: string;
	/** Once the code is used up and before its token is issued, with its subject; a failure voids the code, issuing nothing. */
	pin(redemption: string, subject: string): Promise<void>;
	/**
	 * Once its token passed every check, before it is answered: the token's bundle is on the log,
	 * taken in and signed by then, so a failure voids the code and revokes a token never answered.
	 */
	redeemed(redeemed: Redeemed): Promise<void>;
}

/** The hooks every redemption runs, keyed by name. */
export const redemptionHooks = extensionPoint<RedemptionHook>("code-grant.redemption-hooks", {
	multiplicity: "keyed",
	keyOf: (hook) => hook.name,
});

export * from "./store.ts";
