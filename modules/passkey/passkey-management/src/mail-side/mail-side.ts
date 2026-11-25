import { createHash, createPublicKey, verify, type webcrypto } from "node:crypto";
import type { Keys } from "@mod/keys";
import { firstKey, payloads, type SigningKey } from "@mod/sdk-core-wire";
import type { Users } from "@mod/users";
import { masked } from "../account.ts";
import type { Created, CreationAsk } from "../creation/creation.ts";
import type { Nonces } from "../nonces/nonces.ts";
import { digestOf, openSealed, type SealedRequest } from "../sealed/sealed.ts";
import type { Tokens } from "../tokens/tokens.ts";

/** Why the mail's side refused, for the path's log alone: the screen is answered one word for all. */
export type Refusal = "nonce" | "unopened" | "token" | "revoked" | "full" | "answer" | "recovery";

/**
 * The mail's side answered: the creation statement kept for its request; refused, with why; a
 * statement's own refusal, a fault, with its word; or the opening withdrawn.
 */
export type Answered =
	| { readonly kind: "answered"; readonly statement: string }
	| { readonly kind: "refused"; readonly reason: Refusal }
	| { readonly kind: "unavailable"; readonly reason: string }
	| { readonly kind: "withdrawn" };

/** A recovery asked: the mail's nonce, its request's digest, and E_sig's signature (r‖s, base64url) over them. */
export interface Recovery {
	readonly nonce: string;
	readonly digest: string;
	readonly sig: string;
}

const refused = (reason: Refusal): Answered => ({ kind: "refused", reason });
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/** Whether `signature` (ES256, r‖s, base64url) is E_sig's over `input`. */
function signedBy(key: SigningKey, input: string, signature: string): boolean {
	try {
		const publicKey = createPublicKey({ key: key as webcrypto.JsonWebKey, format: "jwk" });
		return verify(
			"sha256",
			Buffer.from(input, "utf8"),
			{ key: publicKey, dsaEncoding: "ieee-p1363" },
			Buffer.from(signature, "base64url"),
		);
	} catch {
		return false;
	}
}

/**
 * A first key's mail's side (§3.13's step 3, and §C.4's recovery), in the order its D4 settled (§7.5
 * to §7.8): the nonce bound to the request first; the token tried in one write, the identifier's
 * subject and the code; an answer kept read before any creation; a creation made once, kept once,
 * and given only while the token is used by this request.
 */
export function mailSideOver(p: {
	readonly keys: Pick<Keys, "open">;
	readonly nonces: Nonces;
	readonly users: Pick<Required<Users>, "byIdentifier">;
	readonly tokens: Tokens;
	readonly create: (ask: CreationAsk) => Promise<Created>;
}) {
	return {
		mail: async (request: SealedRequest): Promise<Answered> => {
			const q = { nonce: request.nonce, digest: digestOf(request) };
			// The same request again goes on, to take up what a fall left; any other is refused.
			if ((await p.nonces.use(request.nonce, "mail", q.digest)) === "refused")
				return refused("nonce");
			const opened = await openSealed(p.keys, "mail", request, payloads.mailPlain);
			if (opened.kind === "withdrawn") return opened;
			if (opened.kind !== "opened") return refused("unopened");
			const { token, identifier, code } = opened.plain;
			const found = await p.users.byIdentifier(identifier);
			// The identifier's subject is tried against the token's alone: the token names whom it binds.
			const named = found.kind === "user" ? found.user.subject : undefined;
			const tried = await p.tokens.attempt(token, q, named, code);
			if (tried.kind === "refused") return refused("token");
			// An answer kept is read before any creation, so a request taken up after a fall gets it, never another.
			const kept = await p.tokens.answered(q);
			if (kept !== undefined) return { kind: "answered", statement: kept };
			if (tried.kind === "used") return refused("answer");
			const created = await p.create({
				subject: tried.subject,
				account: masked(identifier),
				basis: "first-key",
				evidence: sha256(firstKey.evidenceInput(token)),
				ctHash: opened.digest,
				screen: opened.screen,
				since: tried.since,
			});
			if (created.kind === "refused")
				return created.reason === "revoked" || created.reason === "full"
					? refused(created.reason)
					: { kind: "unavailable", reason: created.reason };
			await p.tokens.keep(q, token, { eSig: opened.screen.eSig, statement: created.statement });
			const given = await p.tokens.answered(q);
			return given !== undefined ? { kind: "answered", statement: given } : refused("answer");
		},
		recover: async (r: Recovery): Promise<Answered> => {
			const kept = await p.tokens.recoverable(r.nonce);
			if (kept?.digest !== r.digest) return refused("recovery");
			if (!signedBy(kept.eSig, firstKey.recoverInput(r.nonce, r.digest), r.sig))
				return refused("recovery");
			const given = await p.tokens.answered({ nonce: r.nonce, digest: r.digest });
			return given !== undefined ? { kind: "answered", statement: given } : refused("recovery");
		},
	};
}
