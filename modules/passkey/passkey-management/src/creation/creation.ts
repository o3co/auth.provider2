import type { Approvals, Issued, Screen } from "@mod/approvals";
import type { Held, PasskeyGenerations } from "@mod/passkeys";
import type { CreationPayload } from "@mod/sdk-core-wire";
import type { SubjectRevocation } from "@mod/subject-revocation";
import { type Ceremonies, freshHandle } from "@mod/webauthn";
import { z } from "zod";
import { nameOf } from "../account.ts";

/** A creation asked for the subject its evidence binds: what its statement names, and the screen it is for. */
export type CreationAsk = {
	readonly subject: string;
	/** The evidence's value the screen computes for itself. */
	readonly evidence: string;
	readonly screen: Screen;
	/** When the evidence began (epoch ms): a revocation of the subject since refuses it. */
	readonly since: number;
	/** The account as shown, never matched: an identifier masked; none, and the creation names it. */
	readonly account?: string;
} & (
	| {
			readonly basis: "first-key";
			/** The sealed request's digest, as the Core opened it: the first key's path's alone. */
			readonly ctHash: string;
	  }
	| {
			readonly basis: "passkey-add";
			/** The key whose approval the passkey-add's creation goes on from, as its JWK (V30). */
			readonly approverKey: ApproverKey;
	  }
	| { readonly basis: "sign-up" }
);

/** The approving key as a creation names it: sdk-core-wire's form, a P-256 or Ed25519 key's JWK where webauthn's `passkeyJwk` gives it. */
export type ApproverKey = NonNullable<CreationPayload["creation"]["approver_key"]>;

export type Created = Issued | { readonly kind: "refused"; readonly reason: "revoked" | "full" };

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
/** An unnamed account's place in webauthn's options, never read: the statement's `user_name` is the name. */
const unnamed = "account";

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
	/** The deployment's name an account no identifier names shows; by default the RP ID. */
	readonly accountName?: string | undefined;
}) {
	return async (ask: CreationAsk): Promise<Created> => {
		if ((await p.revocation.check(ask.subject, ask.since)) === "revoked")
			return { kind: "refused", reason: "revoked" };
		const held = await p.held.of(ask.subject);
		// A key past the most the subject may hold is never asked of the person, nor named in more
		// excluded keys than a creation carries.
		if (held.full) return { kind: "refused", reason: "full" };
		// A generation moved on before the key change is decided is refused there: read apart, it may lag.
		const generation = await p.generations.generation(ask.subject);
		const handle = freshHandle(p.random);
		const read = options.safeParse(
			p.ceremonies.creation(
				unused,
				{ handle, name: ask.account ?? unnamed },
				held.credentials,
				"required",
			),
		);
		// Of another shape, webauthn changed: a fault, never a creation of guessed values.
		if (!read.success)
			throw new TypeError("passkey-management: webauthn's options of another shape");
		const given = read.data;
		// Named by the deployment and a mark of its subject, at most 50 of the RP ID, as `user_name` holds 64.
		const userName =
			ask.account === undefined
				? nameOf(p.accountName ?? given.rp.id.slice(0, 50), ask.subject)
				: undefined;
		return p.approvals.issue({
			purpose: "creation",
			items: {
				...(ask.account === undefined ? {} : { account: ask.account }),
				basis: ask.basis,
				evidence: ask.evidence,
				...(ask.basis === "first-key" ? { ct_hash: ask.ctHash } : {}),
				...(ask.basis === "passkey-add" ? { approver_key: ask.approverKey } : {}),
				subject: ask.subject,
				kg: generation,
				options: {
					user_id: given.user.id,
					...(userName === undefined ? {} : { user_name: userName }),
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
	names: ["account", "basis", "evidence", "ct_hash", "subject", "kg", "approver_key", "options"],
	by: "passkey-management",
} as const;
