import type { BundlePart } from "@mod/grants";
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
	/** The binding the authorization asked for ahead (`dpop_jkt`): the code's tokens hold it, and none other. */
	readonly binding?: Binding;
}

/** An approval as an ID token of its code names it (A38, A21), each as `approvals` gave it, once its record is placed. */
export interface ApprovedFacts {
	/** Its statement's E_sig's thumbprint. */
	readonly esig: string;
	/** Its record's reference on the log. */
	readonly apr: { readonly shard: string; readonly n: number };
	/** When the log accepted its record, in ms: the ID token's authentication time. */
	readonly approvedAt: number;
}

/** What an ID token of a redemption is made from: the code's, as its record holds them. */
export interface IdTokenRequest extends ApprovedFacts {
	readonly subject: string;
	readonly clientId: string;
	readonly nonce: string;
	readonly amr: readonly string[];
	readonly acr?: string;
	readonly scope: readonly string[];
	/** The session's handle, which never lets anyone into it. */
	readonly session: string;
	/** The code's digest, as `digestOf` gives it: the redemption's name, its pin's, and `c_hash`'s source. */
	readonly code: string;
}

/** Makes a redemption's ID token, as a part of its bundle (frame `idToken`), where the scope has `openid`. */
export interface IdTokenMaker {
	/** Read before the bundle starts: what it reads besides the request fails the redemption, recording nothing. */
	part(request: IdTokenRequest): Promise<BundlePart>;
}

/** At most one; two refuse boot. With none, a code asking an ID token is answered `invalid_scope`. */
export const idTokens = extensionPoint<IdTokenMaker>("code-grant.id-tokens", {
	multiplicity: "many",
});

export interface Codes {
	/**
	 * A code for the facts. Throws Unavailable where the store cannot tell, or the session is not
	 * entered at use (closed or short since the caller read it); TypeError for facts the session or
	 * the client contradict.
	 */
	issue(facts: CodeFacts): Promise<string>;
	/**
	 * Sets the root's reference of a code, once: the record its chain roots in, its approval's, which
	 * carries the code's digest and so is placed after the code is made; carried to the bundle unread.
	 * `set` where the code is unused and had none (or had this one), `refused` for any other. With it,
	 * what the approval gives an ID token: required for a code whose scope has `openid`, else a
	 * TypeError. Throws Unavailable where the store cannot tell.
	 */
	root(code: string, root: string, approval?: ApprovedFacts): Promise<"set" | "refused">;
	/** A code's digest, its SHA-256 in base64url: what a record names it by, never the code itself. */
	digestOf(code: string): string;
	/** How long a code lives once issued, as `code-lifetime` says. */
	lifetimeMs(): number;
	/** Whether an ID token is made (a module contributes to `idTokens`): without, an `openid` code redeems for nothing. */
	issuesIdTokens(): boolean;
}

export const codes = contract<Codes>("code-grant");

/** The scope that asks for an ID token (OpenID Connect Core §3.1.2.1). */
export const openid = "openid";

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

export * from "./store/store.ts";
