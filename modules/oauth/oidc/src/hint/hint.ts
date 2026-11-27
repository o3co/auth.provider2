import type { Keys } from "@mod/keys";
import { idTokenTyp } from "../id-token/id-token.ts";

/** What a hint names: the subject of an ID token of this issuer for the client, or why it is none. */
export type HintSubject = { readonly subject: string } | { readonly refused: string };

/** An ID token given back as a hint, read. */
export interface HintReader {
	subjectOf(hint: string, clientId: string): Promise<HintSubject>;
}

/**
 * The reader of a hint (OIDC Core §3.1.2.2): verified by the authority's ring as an ID token, so by
 * any key of it that still verifies, a previous one until its `expires-at`; of this issuer, for the
 * client; its `exp` not checked, as the person's tap, not the hint, is the authentication.
 */
export function hintReader(p: {
	readonly verify: Keys["verify"];
	readonly issuer: string;
}): HintReader {
	return {
		subjectOf: async (hint, clientId) => {
			const read = await p.verify("authority", hint, idTokenTyp);
			if (read.kind !== "valid")
				return { refused: `the id_token_hint is not an ID token of this issuer (${read.reason})` };
			const { iss, aud, sub } = read.claims;
			if (iss !== p.issuer) return { refused: "the id_token_hint is of another issuer" };
			const audiences: readonly unknown[] = Array.isArray(aud) ? aud : [aud];
			if (!audiences.includes(clientId))
				return { refused: "the id_token_hint is for another client" };
			if (typeof sub !== "string" || sub === "")
				return { refused: "the id_token_hint names no subject" };
			return { subject: sub };
		},
	};
}
