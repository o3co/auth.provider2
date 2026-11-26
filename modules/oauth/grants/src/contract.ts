import type { Client } from "@mod/clients";
import type { BodyKind, HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type {
	AccessGrant,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
	SubjectKind,
} from "@mod/tokens";
import type { TargetVerdict } from "./audience/audience.ts";
import type { BundleRequest, Refused } from "./issuance/issuance.ts";

export type OAuthError =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope"
	| "invalid_target";

export type GrantOutcome =
	| { readonly kind: "issued"; readonly body: Readonly<Record<string, unknown>> }
	| {
			readonly kind: "error";
			/** An OAuth error code, or one the grant owns (such as a polled grant's). */
			readonly error: OAuthError | (string & {});
			readonly description?: string;
			/**
			 * `401` or `429` when the grant names it; otherwise `400`, or `401` for `invalid_client`.
			 * Another is ignored.
			 */
			readonly status?: 400 | 401 | 429;
			/** For a `429`, too many requests: how long to wait, in ms, answered as `retry-after` in whole seconds. */
			readonly retryAfterMs?: number;
			/** More members of the error body, passed through unread but for the names an error answer drops. */
			readonly members?: Readonly<Record<string, unknown>>;
	  };

export interface GrantInput {
	readonly request: HttpRequest;
	readonly client: Client;
	/** A parameter's single string value; repeated parameters never reach a grant. */
	param(name: string): string | undefined;
	/** A parameter as sent: a JSON member of any type, or a form's single value. */
	value(name: string): unknown;
	/** The audience to issue: the default, or what the request asks within the ceiling; its error is the answer. */
	target(audience: readonly string[], within: (audience: string) => boolean): TargetVerdict;
	/** The binding every token issued for this request carries. */
	readonly binding?: Binding;
	/** What the grant's own `identify` answered with the client, handed back unread; none for a client that authenticated. */
	readonly identified?: unknown;
	/**
	 * What the client's authentication verified (its method's `proof`), handed on unread: its owner
	 * reads it. None for a client a grant identified, or one whose method verified nothing to carry.
	 */
	readonly authenticated?: unknown;
	/**
	 * Whether `issue` would allow the grant now; asked before anything is used up. The grant says
	 * whom it issues for: its subject and the subject's kind, a client's own being the client itself.
	 */
	admits(
		grant: AccessGrant,
		from?: Pick<IssuanceRequest, "session" | "continuing">,
	): Promise<{ readonly kind: "allowed" } | Refused>;
	/**
	 * Issues one bundle with the request's grant type and binding once the policies allow it again:
	 * its start recorded, its tokens made with that record's acceptance time as their issue time,
	 * recorded once and signed after; answered once judged. `session` and `continuing` go to the
	 * policies, the rest to the token.
	 */
	issue(
		bundle: BundleRequest,
		from?: Pick<IssueLimits, "notAfter" | "lifetimeSeconds"> &
			Pick<IssuanceRequest, "session" | "continuing">,
	): Promise<
		| {
				readonly kind: "issued";
				readonly access: IssuedAccess;
				/**
				 * Each part's token, as its owner signed it, in the order asked; none where none was asked.
				 * A `family` part the token endpoint left out, its approval's key no longer live (V24), is
				 * answered undefined at its place.
				 */
				readonly parts?: readonly (string | undefined)[];
		  }
		| Refused
	>;
}

/** How a grant holds the tokens it issues to a client to a key of that client's (`Grant.keyHold`). */
export type KeyHold = "authorization" | "family" | "assertion";

export interface Grant {
	readonly grantType: string;
	/** The bodies the grant takes; a form only when left out. */
	readonly bodies?: readonly Exclude<BodyKind, "none">[];
	/** Whether it takes its audience from the request, through `target` or reading the parameters itself. */
	readonly targets?: true;
	/**
	 * What it reads that a browser sends by itself: `cookie` for a grant reading the session's cookie,
	 * which then checks the request's origin itself; `none` otherwise. A declaration, never a proof.
	 */
	readonly readsAmbient: "none" | "cookie";
	/**
	 * The kind of subject every token it issues is for (`tokens`' word): `user` for a person's,
	 * `client` for the client's own. A declaration the token endpoint reads, never a proof.
	 */
	readonly subjectKind?: SubjectKind;
	/**
	 * How each access token and refresh credential it issues to a client is held to a key of that
	 * client's, so one who relays the request cannot use what it gets without the key: `authorization`,
	 * to the key the client's signed authorization named ahead; `family`, to its family's key, which
	 * that authorization named; `assertion`, to the key that signed the client's assertion, proved by
	 * that same key. Left out, the grant declares no such hold. An ID token is held by none. A
	 * declaration the token endpoint reads, never a proof.
	 */
	readonly keyHold?: KeyHold;
	/**
	 * For a request that names no client and carries nothing a client authenticates with: the client
	 * the grant's own credential identifies, with what it checked to tell (`identified`), or its
	 * refusal. Only a grant that can tell has it. The client it names is one the operator registered
	 * with no credentials (public, method `none`); the endpoint refuses any other.
	 */
	identify?(
		input: Pick<GrantInput, "request" | "param" | "value">,
	): Promise<IdentifiedClient | Extract<GrantOutcome, { readonly kind: "error" }>>;
	handle(input: GrantInput): Promise<GrantOutcome | Refused>;
}

/** The client a grant's own credential identifies, and what the grant checked to tell, for its `handle`. */
export interface IdentifiedClient {
	readonly kind: "client";
	readonly client: string;
	readonly identified?: unknown;
}

export const grants = extensionPoint<Grant>("grants", {
	multiplicity: "keyed",
	keyOf: (grant) => grant.grantType,
});

/** The grant types composed at boot, as the token endpoint dispatches to them. */
export const composedGrants = contract<ReadonlySet<string>>("grants.composed");

/**
 * The index of first-party grants: each grant type a module of this release serves, by that
 * module's name (its package's, without the scope), as each module's manifest declares it
 * (`grantTypes`). Words as strings alone: it reads no module's contract or behaviour, so a module
 * named here need not be composed. It has no prototype, so a name every object has (`constructor`,
 * `__proto__`) is a type it does not list.
 */
export const grantServers: Readonly<Record<string, string>> = Object.freeze(
	Object.assign(Object.create(null) as Record<string, string>, {
		authorization_code: "code-grant",
		client_credentials: "client-credentials",
		refresh_token: "refresh",
	}),
);

export * from "./audience/audience.ts";
export * from "./issuance/issuance.ts";
