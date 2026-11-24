import { createHash } from "node:crypto";
import { tokenRules } from "@mod/authority-rules";
import type { Target } from "@mod/claims-selection";
import type { IdTokenMaker, IdTokenRequest } from "@mod/code-grant";
import type { BundlePart } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import type { Keys, Prepared } from "@mod/keys";
import { tokens } from "@mod/transparency-wire";
import { type Claim, claimsOf } from "../claims/claims.ts";

/** An ID token's `typ`: the standard `JWT`. Telling token kinds apart is each receiver's check of its own kind. */
export const idTokenTyp = "JWT";

/** What the ID token is made over. */
export interface IdTokenParts {
	readonly keys: Pick<Keys, "prepare" | "sign">;
	/** `issuer`'s URL, the ID token's `iss`. */
	readonly issuer: string;
	/** How long an ID token lives, in seconds. */
	readonly lifetimeS: number;
	/** The subject's attributes, from the source `subject-attributes` answers with; none where neither can say. */
	readonly attributes: (
		subject: string,
		session: string,
	) => Promise<
		| { readonly vouched: boolean; readonly attributes: Readonly<Record<string, unknown>> }
		| undefined
	>;
	/** What the redemption's pinned selection asks of the ID token; none for a code without one. */
	readonly asked: (code: string) => Promise<Target | undefined>;
}

/** What a part prepared holds: the header fixed and the claims' exact text, signed as they are. */
interface Ready {
	readonly header: Prepared;
	readonly claimsText: string;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/** The claims released for the code's scope and what its pin asks; `email_verified` only where users vouches. */
async function releasedFor(p: IdTokenParts, r: IdTokenRequest): Promise<Record<string, Claim>> {
	const known = await p.attributes(r.subject, r.session);
	if (!known) return {};
	const { email_verified, ...released } = claimsOf(
		known.attributes,
		r.scope,
		await p.asked(r.code),
	);
	return known.vouched && email_verified !== undefined ? { ...released, email_verified } : released;
}

/**
 * The ID token's claims, a closed set: the released ones first, so none of them stands for one of
 * these. `iat` is the bundle's start's acceptance; `auth_time`, the approval's record's.
 */
function claimsFor(
	p: IdTokenParts,
	r: IdTokenRequest,
	released: Record<string, Claim>,
	acceptedAt: number,
) {
	const iat = Math.floor(acceptedAt / 1000);
	// The approval's record's acceptance, as the monitor checks it: one after the bundle's start is no
	// order the log keeps, and no ID token is made of it.
	const authTime = Math.floor(r.approvedAt / 1000);
	if (authTime > iat) throw new Unavailable("oidc");
	return {
		...released,
		iss: p.issuer,
		sub: r.subject,
		aud: r.clientId,
		azp: r.clientId,
		iat,
		exp: iat + p.lifetimeS,
		auth_time: authTime,
		nonce: r.nonce,
		sid: r.session,
		c_hash: tokenRules.idToken.cHash(r.code),
		amr: r.amr,
		...(r.acr === undefined ? {} : { acr: r.acr }),
		esig: r.esig,
		apr: { shard: r.apr.shard, n: r.apr.n },
	};
}

/**
 * The ID token of a redemption, as a part of its bundle (A40): prepared with the start's acceptance
 * time, its digest that of its header and claims texts as the log names a token's, and signed by
 * the authority's ring after the bundle's receipts. Its receipt is not written into it yet (`txr`).
 */
export function idTokenMaker(p: IdTokenParts): IdTokenMaker {
	return {
		part: async (request): Promise<BundlePart> => {
			// Read before the bundle starts: a read that fails records nothing.
			const released = await releasedFor(p, request);
			return {
				frame: "idToken",
				prepare: async (acceptedAt) => {
					const header = p.keys.prepare("authority", idTokenTyp);
					const claimsText = JSON.stringify(claimsFor(p, request, released, acceptedAt));
					const digested = tokens.digestInput(header.headerText, claimsText);
					if ("error" in digested)
						throw new TypeError(`oidc: an ID token's texts: ${digested.error}`);
					const ready: Ready = { header, claimsText };
					return { prepared: ready, digest: sha256(digested.input) };
				},
				sign: async (prepared) => {
					const { header, claimsText } = prepared as Ready;
					const signed = await p.keys.sign(header, new TextEncoder().encode(claimsText));
					if (signed.kind !== "signed") throw new Unavailable("oidc");
					return signed.jws;
				},
			};
		},
	};
}
