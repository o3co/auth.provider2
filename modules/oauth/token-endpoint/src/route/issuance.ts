import type { GrantInput, Refused, SessionIssuance } from "@mod/grants";
import type { Binding } from "@mod/sender-binding";
import {
	type AccessGrant,
	type AccessTokenIssuance,
	type IssuanceRequest,
	type Issued,
	type IssueLimits,
	referenceOf,
	type SubjectKind,
	type Tokens,
} from "@mod/tokens";

/** What a request's grant issued through `issue`: its subjects, each with its kind; the names of the claims it added. */
export interface IssuedBundle {
	readonly subjects: Map<string, Pick<AccessGrant, "subject" | "subjectKind">>;
	readonly added: Set<string>;
}

export const bundleOf = (): IssuedBundle => ({ subjects: new Map(), added: new Set() });

/** How a grant's `issue` issues: the endpoint's runs a bundle; the test caller's signs at once. */
export interface Issuing {
	readonly admits: AccessTokenIssuance["admits"];
	issue(ask: {
		readonly request: IssuanceRequest;
		readonly limits: IssueLimits;
		readonly root?: string;
	}): Promise<Issued>;
	readonly revokeReferenced: Tokens["revokeReferenced"];
}

/**
 * A grant's `admits` and `issue`, with the binding; `issue` tells `told` of a token from a session,
 * and notes in `bundle` each token's subject and the names of the claims the grant added to it. A
 * bundle whose subject's kind is not the one the grant declares (`declared`) is the grant's fault.
 */
export function issuanceFor(
	issuing: Issuing,
	grantType: string,
	binding: Binding | undefined,
	told: readonly SessionIssuance[] = [],
	bundle: IssuedBundle = bundleOf(),
	declared?: SubjectKind,
) {
	const bound = binding ? { binding } : {};
	let bundled = false;
	const requestOf = (
		grant: AccessGrant,
		{ session, continuing }: Pick<IssuanceRequest, "session" | "continuing">,
	) => ({
		grant,
		grantType,
		...(session === undefined ? {} : { session }),
		...(continuing === undefined ? {} : { continuing }),
	});
	const admits: GrantInput["admits"] = async (grant, from = {}) => {
		const judged = await issuing.admits(requestOf(grant, from));
		return judged.kind === "allowed" ? judged : { kind: "refused", refusal: judged };
	};
	const issue: GrantInput["issue"] = async (asked, from = {}) => {
		// One request, one bundle (A40): a second is the grant's maker's mistake.
		if (bundled) throw new TypeError("token-endpoint: a request issues one bundle");
		bundled = true;
		const { session, continuing: _, ...limits } = from;
		// Read once: tokens signs the subject the bundle notes, whatever the grant answers later.
		const grant = { ...asked.access };
		const { subject, subjectKind } = grant;
		if (declared !== undefined && subjectKind !== declared) {
			throw new TypeError(
				`token-endpoint: ${grantType} issued for a subject kind it does not declare`,
			);
		}
		const root = asked.root === undefined ? {} : { root: asked.root };
		const issued = await issuing.issue({
			request: requestOf(grant, from),
			limits: { ...limits, ...bound },
			...root,
		});
		if (issued.kind !== "issued") return { kind: "refused", refusal: issued } satisfies Refused;
		bundle.subjects.set(JSON.stringify([subjectKind, subject]), { subject, subjectKind });
		// Named from what tokens judged and signed, never the grant read again.
		for (const name of issued.access.addedClaims ?? []) bundle.added.add(name);
		if (session === undefined) return issued;
		const { id, expiresAt } = issued.access;
		try {
			for (const one of told) await one.issued(session, { id, expiresAt });
		} catch (error) {
			// The failure told is the one thrown on: a token whose revocation fails too is handed to no one.
			await issuing.revokeReferenced(referenceOf(issued.access)).catch(() => undefined);
			throw error;
		}
		return issued;
	};
	return { admits, issue };
}

/** The one answer to a refused issuance, whatever the grant. */
export const refusedAnswer = ({ refusal }: Refused) =>
	({ kind: "error", error: "invalid_grant", description: refusal.description }) as const;
