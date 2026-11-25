import type { Client } from "@mod/clients";
import type { BodyKind, HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type {
	AccessGrant,
	IssuanceRefused,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
	SubjectKind,
} from "@mod/tokens";

export type OAuthError =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope"
	| "invalid_target";

/** An issuance a policy refused: a grant returns it unread, and the endpoint answers it. */
export interface Refused {
	readonly kind: "refused";
	readonly refusal: IssuanceRefused;
}

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

/** For an issuance's audience: the request's parameters, the audience when none is asked, and whether the issuance may have another (its owner decides). */
export interface TargetRequest {
	readonly param: (name: string) => string | undefined;
	readonly audience: readonly string[];
	readonly within: (audience: string) => boolean;
}
export type TargetVerdict =
	| { readonly kind: "audience"; readonly audience: readonly string[] }
	| { readonly kind: "error"; readonly error: "invalid_target"; readonly description: string };
/** A rule for the audience a request asks for, as resource indicators (RFC 8707) contribute. */
export interface TargetRule {
	target(request: TargetRequest): TargetVerdict;
	/** For a grant that takes no audience, or another endpoint that asks: a refusal when the request asks one anyway. */
	untargeted?(
		request: Pick<TargetRequest, "param">,
	): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
	/** For a parameter sent more than once: a refusal when it is one the rule reads. */
	repeated?(name: string): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
}
/** At most one; two refuse boot. */
export const targetRules = extensionPoint<TargetRule>("grants.target-rules", {
	multiplicity: "many",
});
/** The composed rule, provided by the token endpoint; with none, the default audience, the request unread. */
export const targets = contract<TargetRule>("grants.targets");

/**
 * One bundle a grant issues: its tokens recorded once, under its start, before any is signed. It holds
 * an access token; its subject's kind names the flow it is recorded on, a person's or the client's own.
 */
export interface BundleRequest {
	/** Its root's reference: the record its chain roots in, where that record is on the log; none where it is not. */
	readonly root?: string;
	/** How a person's bundle roots there: by an approval's code, or by a family's refresh. */
	readonly via?: Rooting;
	readonly access: AccessGrant;
	/** The tokens it carries beside its access token, each its owner's, recorded in the same bundle. */
	readonly parts?: readonly BundlePart[];
}

/**
 * How a person's bundle roots: by an approval's code, or by a family's refresh, the rotation its
 * start names read by the token endpoint from the flow's applied state.
 */
export type Rooting =
	/** By an approval's code: its digest (its SHA-256, base64url, A21), which the start names beside its client (V24). */
	{ readonly via: "code"; readonly code?: string } | { readonly via: "refresh" };

/**
 * A token a bundle carries beside its access token (A40), made by its owner: prepared with the
 * start's acceptance time before the bundle is recorded, its digest recorded with the access
 * token's, and signed only after the bundle's receipts, with its own receipt and the bundle's
 * record. Its `commit`, where it has one, runs once the bundle is taken in as its owner's `took`
 * (V12), before any token is answered: a failure answers none, the bundle on the log all the same.
 */
export interface BundlePart {
	readonly frame: "idToken" | "family";
	prepare(acceptedAt: number): Promise<{ readonly prepared: unknown; readonly digest: string }>;
	sign(prepared: unknown, receipt: string, placed: BundlePlaced): Promise<string>;
	commit?(prepared: unknown, placed: BundlePlaced): Promise<void>;
}

/** The bundle's record on the log: its id (a family it makes is named by it) and its acceptance time. */
export interface BundlePlaced {
	readonly id: string;
	readonly acceptedAt: number;
}

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
				/** Each part's token, as its owner signed it, in the order asked; none where none was asked. */
				readonly parts?: readonly string[];
		  }
		| Refused
	>;
}

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

/** Told of each access token `issue` makes from a session, before the grant answers it. */
export interface SessionIssuance {
	/** A failure revokes the token, and `issue` throws it on. */
	issued(session: string, access: Pick<IssuedAccess, "id" | "expiresAt">): Promise<void>;
}

export const sessionIssuances = extensionPoint<SessionIssuance>("grants.session-issuances", {
	multiplicity: "many",
});

/** What a token is tied to by one tie; `reason` is read after the token's name ("family has ended"). */
export type TokenTieAnswer =
	| { readonly kind: "none" }
	| { readonly kind: "ended"; readonly reason: string }
	| {
			readonly kind: "held";
			/** When the tie ends, in epoch ms: a token issued from it ends by then. */
			readonly ends?: number;
			/** The session a token issued from it is issued from. */
			readonly session?: string;
			/** Adds a token issued from it, for its subject: false when the tie ended meanwhile. */
			join(issued: Pick<IssuedAccess, "id" | "expiresAt">, subject: string): Promise<boolean>;
	  };

/**
 * One thing a token this provider issued is tied to, kept by its owner: its family, its session.
 * Asked only of a token this provider issued and has verified; throws Unavailable when it cannot tell.
 */
export interface TokenTie {
	readonly name: string;
	tieOf(tokenId: string): Promise<TokenTieAnswer>;
}

export const tokenTies = extensionPoint<TokenTie>("grants.token-ties", {
	multiplicity: "keyed",
	keyOf: (tie) => tie.name,
});
