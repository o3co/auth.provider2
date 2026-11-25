import type { Approvals, Issued } from "@mod/approvals";
import type { Held, PasskeyGenerations } from "@mod/passkeys";
import type { SubjectRevocation } from "@mod/subject-revocation";
import { type Ceremonies, freshHandle } from "@mod/webauthn";
import { z } from "zod";
import type { Screen } from "../sealed/sealed.ts";

/** A creation asked for the subject its evidence binds: what its statement names, and the screen it is for. */
export interface CreationAsk {
	readonly subject: string;
	/** The identifier, masked: shown, never matched. */
	readonly account: string;
	readonly basis: "first-key";
	/** The evidence's value the screen computes for itself. */
	readonly evidence: string;
	/** The sealed request's digest, as the Core opened it: the first key's path's alone. */
	readonly ctHash: string;
	readonly screen: Screen;
	/** When the evidence began (epoch ms): a revocation of the subject since refuses it. */
	readonly since: number;
}

export type Created = Issued | { readonly kind: "refused"; readonly reason: "revoked" };

/** The parts of webauthn's options a creation names, read as they must be: webauthn's contract types them `unknown`. */
const options = z.object({
	rp: z.object({ id: z.string().min(1) }),
	user: z.object({ id: z.string().min(1) }),
	pubKeyCredParams: z
		.array(z.object({ alg: z.union([z.literal(-7), z.literal(-8), z.literal(-257)]) }))
		.min(1),
	excludeCredentials: z.array(z.object({ id: z.string().min(1) })),
});

/** A challenge's place held while webauthn gives the options: the screen derives the real one from the statement. */
const unused = "A".repeat(43);

/**
 * A creation statement made (§3.13's registration, step 2): for a subject its evidence binds and no
 * revocation followed, naming its key generation, the keys it holds as excluded, and webauthn's options
 * for a new key with a fresh handle; signed by approvals for the screen.
 */
export function creationOver(p: {
	readonly approvals: Pick<Approvals, "issue">;
	readonly ceremonies: Pick<Ceremonies, "creation">;
	readonly held: { of(subject: string): Promise<Held> };
	readonly generations: PasskeyGenerations;
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly random: (bytes: number) => Uint8Array;
}) {
	return async (ask: CreationAsk): Promise<Created> => {
		if ((await p.revocation.check(ask.subject, ask.since)) === "revoked")
			return { kind: "refused", reason: "revoked" };
		const held = await p.held.of(ask.subject);
		// A generation moved on before the key change is decided is refused there: read apart, it may lag.
		const generation = await p.generations.generation(ask.subject);
		const handle = freshHandle(p.random);
		const read = options.safeParse(
			p.ceremonies.creation(unused, { handle, name: ask.account }, held.credentials, "required"),
		);
		// Of another shape, webauthn changed: a fault, never a creation of guessed values.
		if (!read.success)
			throw new TypeError("passkey-management: webauthn's options of another shape");
		const given = read.data;
		return p.approvals.issue({
			purpose: "creation",
			items: {
				account: ask.account,
				basis: ask.basis,
				evidence: ask.evidence,
				ct_hash: ask.ctHash,
				subject: ask.subject,
				kg: generation,
				options: {
					user_id: given.user.id,
					rp_id: given.rp.id,
					exclude_credentials: given.excludeCredentials.map((c) => c.id),
					algorithms: given.pubKeyCredParams.map((c) => c.alg),
				},
			},
			screen: ask.screen,
			by: ask.subject,
		});
	};
}

/** The creation's items this package fills, every one its schema names. */
export const creationItems = {
	purpose: "creation",
	names: ["account", "basis", "evidence", "ct_hash", "subject", "kg", "options"],
	by: "passkey-management",
} as const;
