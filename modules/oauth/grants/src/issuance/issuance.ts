import { extensionPoint } from "@mod/kernel";
import type { AccessGrant, IssuanceRefused, IssuedAccess } from "@mod/tokens";

/** An issuance a policy refused: a grant returns it unread, and the endpoint answers it. */
export interface Refused {
	readonly kind: "refused";
	readonly refusal: IssuanceRefused;
}

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
	{ readonly via: "code"; readonly code: string } | { readonly via: "refresh" };

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

/** Told of each access token `issue` makes from a session, before the grant answers it. */
export interface SessionIssuance {
	/** A failure revokes the token, and `issue` throws it on. */
	issued(session: string, access: Pick<IssuedAccess, "id" | "expiresAt">): Promise<void>;
}

export const sessionIssuances = extensionPoint<SessionIssuance>("grants.session-issuances", {
	multiplicity: "many",
});
