import type { AddedClaims } from "@mod/added-claims";
import { deepFreeze, Unavailable } from "@mod/kernel";
import { checkClaims } from "../claims/claims.ts";
import type {
	Admitted,
	IssuancePolicy,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
	PreparedAccess,
	Tokens,
} from "../contract.ts";
import { actorSnapshot } from "../limits.ts";

/** How far ahead of the clock an authentication time may be, as 0.17 allowed. */
export const authenticatedAheadMs = 300_000;

/** How long the policies may take together unless the section says: its default. */
export const issuanceTimeoutMs = 10_000;

/** What a client is told of an issuance refused for a reason it is not to learn. */
export const refusedDescription = "issuance refused";

/** What a policy answers, or unavailable once the deadline passes: a policy that never answers holds nothing. */
const within = <T>(answer: Promise<T>, deadline: AbortSignal): Promise<T> => {
	// One answering after the deadline is dropped, its failure included.
	answer.catch(() => {});
	return new Promise<T>((done, failed) => {
		const passed = () => failed(new Unavailable("tokens"));
		if (deadline.aborted) return passed();
		deadline.addEventListener("abort", passed, { once: true });
		answer.then(done, failed).finally(() => deadline.removeEventListener("abort", passed));
	});
};

/**
 * The judgment `admits` and `issue` share: tokens' own rule first, then each policy in name order,
 * all of them within one deadline; past it, unavailable, and each policy's signal aborts.
 */
export function judging(
	policies: readonly IssuancePolicy[],
	now: () => number,
	deadlineOf: () => AbortSignal = () => AbortSignal.timeout(issuanceTimeoutMs),
) {
	const ordered = policies.toSorted((a, b) => (a.name < b.name ? -1 : 1));
	return async (request: IssuanceRequest): Promise<Admitted> => {
		const { authenticatedAt } = request.grant;
		if (authenticatedAt !== undefined && authenticatedAt > now() + authenticatedAheadMs) {
			return {
				kind: "refused",
				policy: "tokens",
				reason: "authenticated_ahead",
				description: "the authentication time is ahead of the clock",
			};
		}
		// The policies read one frozen copy, so none can change what another or the issuing sees.
		const asked = deepFreeze(structuredClone(request));
		const deadline = deadlineOf();
		for (const { name, judge } of ordered) {
			if (deadline.aborted) throw new Unavailable("tokens");
			const verdict = await within(judge(asked, deadline), deadline);
			if (verdict.kind === "allowed") continue;
			// Anything but allowed refuses, so a policy's unreadable answer never issues.
			return verdict.kind === "refused"
				? { ...verdict, policy: name }
				: { kind: "refused", policy: name, reason: "unreadable", description: refusedDescription };
		}
		return { kind: "allowed" };
	};
}

/** A token made ready: its texts, and its signing, answering it and what keeps it once handed out. */
export interface MadeAccess {
	readonly headerText: string;
	readonly claimsText: string;
	signed(): Promise<
		{ readonly access: IssuedAccess; readonly keep?: () => void } | { readonly kind: "too-large" }
	>;
}

/** The making once the judgment allows it; `askedAt`, before the policies, is the token's `iat`. */
export type MakeAccess = (
	grant: IssuanceRequest["grant"],
	askedAt: number,
	limits?: IssueLimits,
) => MadeAccess;

/** tokens' own refusal of a token past what it reads once signed: handed to no one. */
const tooLarge = {
	kind: "refused",
	policy: "tokens",
	reason: "token_too_large",
	description: "too large",
} as const;

/** The least a token may have left once signed: a second. */
const leastLeftMs = 1000;

/** tokens' own refusal of a token with less than a second left once signed. */
const noLifetimeLeft = {
	kind: "refused",
	policy: "tokens",
	reason: "no_lifetime_left",
	description: "expired",
} as const;

/**
 * The request with the claims its grant adds checked and copied, before anything else reads them;
 * an empty set is none. Throws TypeError, the grant's maker's mistake, on claims outside the rules
 * or an actor chain deeper than tokens reads, counted before anything copies it.
 */
function checkedRequest(
	request: IssuanceRequest,
	addedOf: (given: unknown) => AddedClaims | undefined,
): IssuanceRequest {
	// Each of the caller's properties is read once: what is checked is what is copied and signed.
	const { grant: given, ...rest } = request;
	const { claims: added, actor: chain, ...grant } = given;
	const actor = actorSnapshot(chain);
	const claims = addedOf(added);
	checkClaims(grant, claims);
	return {
		...rest,
		grant: { ...grant, ...(actor ? { actor } : {}), ...(claims ? { claims } : {}) },
	};
}

/**
 * `admits`, `prepare`, `sign` and `issue` over the judgment and the making, alike for tokens and its
 * stand-in; what the client is told is left of a lifetime runs from when its signing is done.
 */
export function issuing(
	judge: (request: IssuanceRequest) => Promise<Admitted>,
	make: MakeAccess,
	now: () => number,
	/** `added-claims`' check of a grant's claims, under the section's limits. */
	addedOf: (given: unknown) => AddedClaims | undefined,
): Pick<Tokens, "admits" | "prepare" | "sign" | "issue"> {
	// Only what this prepared is signed, so the texts are the ones fixed, whatever came between.
	const made = new WeakMap<PreparedAccess, MadeAccess>();
	const prepare: Tokens["prepare"] = async (request, limits) => {
		// One frozen copy, taken before anything waits, is both what the policies judge and what is
		// made: a caller changing its own grant or limits meanwhile changes neither.
		const taken = deepFreeze(
			structuredClone({ request: checkedRequest(request, addedOf), limits }),
		);
		// When it was asked, with that copy: the token's iat, so the policies' wait cannot move it past a boundary.
		const askedAt = now();
		const judged = await judge(taken.request);
		if (judged.kind === "refused") return judged;
		const access = make(taken.request.grant, askedAt, taken.limits);
		const { headerText, claimsText } = access;
		const prepared = Object.freeze({ kind: "prepared" as const, headerText, claimsText });
		made.set(prepared, access);
		return prepared;
	};
	const sign: Tokens["sign"] = async (prepared) => {
		const access = made.get(prepared);
		if (!access) throw new TypeError("tokens: only an access token this prepared is signed");
		const signed = await access.signed();
		if ("kind" in signed) return tooLarge;
		const { access: issued, keep } = signed;
		// Less than a second left once signed, its end come, its cap passed or its signing slow: handed
		// to no one, and nothing of it kept.
		const leftMs = issued.expiresAt - now();
		if (leftMs < leastLeftMs) return noLifetimeLeft;
		keep?.();
		// Rounded up, so a token signed at once answers its whole lifetime.
		return { kind: "issued", access: { ...issued, expiresIn: Math.ceil(leftMs / 1000) } };
	};
	return {
		admits: async (request) => judge(checkedRequest(request, addedOf)),
		prepare,
		sign,
		issue: async (request, limits) => {
			const prepared = await prepare(request, limits);
			return prepared.kind === "refused" ? prepared : sign(prepared);
		},
	};
}
