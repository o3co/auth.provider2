import type { Client } from "@mod/clients";
import { contract, extensionPoint } from "@mod/kernel";
import type { AuthorizationItems } from "@mod/sdk-core-wire";

export { type JarVerifying, jarVerified, type VerifiedJar } from "./jar/jar.ts";

/** A login's start as the screen sent it: each field's text, by its name in `front-core-wire`. */
export type StartFields = Readonly<Record<string, string>>;

/**
 * Where a login's request comes from: the JAR's compact bytes it names, a refusal, or none where its
 * fields are not this source's. Exactly one source answers each start; one that answers a start
 * naming a `requestUri` has resolved that `request_uri`, which T then names.
 */
export interface RequestSource {
	readonly name: string;
	/** Whether this source is the only one taken: then no other is, the JAR by value among them. */
	readonly only?: boolean;
	jarOf(
		fields: StartFields,
		client: Client,
	): Promise<
		| { readonly jar: string }
		| { readonly refused: { readonly error: string; readonly description: string } }
		| undefined
	>;
}

/** The sources of a login's request, keyed by name: the JAR sent by value is `authorize`'s own. */
export const requestSources = extensionPoint<RequestSource>("authorize.request-sources", {
	multiplicity: "keyed",
	keyOf: (source) => source.name,
});

/**
 * How to answer a person with no passkey: whether this authorization may lead the screen to offer
 * `create()`. With no sign-up offered, a hint for the screen's display alone, outside T's signature:
 * whoever registers a key judges again whether it may. With one offered (`signUpOffers`), it is the
 * sign-up's permission too: kept on T's record at its issue, never judged again, a new subject made
 * on it.
 */
export interface WithoutPasskey {
	allows(p: { readonly client: Client; readonly items: AuthorizationItems }): Promise<boolean>;
}

/** At most one; with none, a person with no passkey is refused. */
export const withoutPasskey = extensionPoint<WithoutPasskey>("authorize.without-passkey", {
	multiplicity: "many",
});

/**
 * What an OpenID request's `claims` (OIDC Core §5.5) select at the finish: none asked; a selection,
 * kept for the code by `keep` (its digest, its lifetime, the subject) before the code is rooted; a
 * `sub` asked that is not the subject; an essential acr the login does not meet.
 */
export type ClaimsPicked =
	| { readonly kind: "none" }
	| {
			readonly kind: "selected";
			keep(digest: string, lifetimeMs: number, subject: string): Promise<void>;
	  }
	| { readonly kind: "otherSubject" }
	| { readonly kind: "acrUnmet" };

/**
 * An OpenID request's `claims` parameter, read by the module that keeps what they select: at the
 * start, before T is made, why it is refused (none where it is not); at the finish, before the
 * session opens, what it selects by the client's allowance and what the person agreed to in T.
 */
export interface RequestClaims {
	refusal(claims: unknown, openid: boolean): string | undefined;
	select(
		client: Client,
		subject: string,
		scope: readonly string[],
		claims: unknown,
		/** The acr the login meets, which an essential acr asked is held to. */
		acr: string | undefined,
	): Promise<ClaimsPicked>;
}

/** At most one; two refuse boot. */
export const requestClaims = extensionPoint<RequestClaims>("authorize.request-claims", {
	multiplicity: "many",
});

/**
 * A person's sign-up (F1), offered by the module that continues it (`/continue`'s stage `sign-up`):
 * its name. With one, a T whose screen may offer `create()` allows its sign-up at its issue.
 */
export interface SignUpOffer {
	readonly by: string;
}

/** At most one; with none, no T allows a sign-up. */
export const signUpOffers = extensionPoint<SignUpOffer>("authorize.sign-up-offers", {
	multiplicity: "many",
});

declare const storedReservation: unique symbol;
/** A JAR's reservation as kept: opaque to the store. */
export type StoredReservation = { readonly [storedReservation]: true };

/** Where each JAR's one use is kept, by its client and `jti`. Throws Unavailable when it cannot tell. */
export interface JarReservations {
	/** Keeps the record for its lifetime, unless one is kept already. */
	create(key: string, record: StoredReservation, lifetimeMs: number): Promise<"created" | "exists">;
	read(key: string): Promise<StoredReservation | undefined>;
	/** Changes the record from what it holds; `change` runs again on a lost race. None where none is kept. */
	change(
		key: string,
		change: (current: StoredReservation) => { readonly value: StoredReservation } | undefined,
	): Promise<{ readonly before: StoredReservation; readonly after: StoredReservation } | undefined>;
}

export const jarReservations = contract<JarReservations>("authorize.jar-reservations");

/** What the reservations' place must be, each a guarantee its wiring declares. */
export const jarReservationsNeeds = {
	/** A reservation lost to eviction or failover would let one JAR start two statements. */
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** A stale read could take a used JAR for a fresh one. */
	confirmedReads: true,
	/** A reservation written outside the provider would hand one request's statement to another. */
	authenticated: true,
} as const;
