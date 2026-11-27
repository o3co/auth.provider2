import { z } from "zod";
import { bytes32, label } from "../primitives.ts";

/** The algorithms a passkey may be of, as COSE numbers them: ES256, EdDSA (Ed25519) and RS256. */
const passkeyAlgorithm = z.union([z.literal(-7), z.literal(-8), z.literal(-257)]);

const userName = label.refine((name) => name.trim() !== "");

/**
 * The key that approved a passkey-add, as a JWK of P-256 or Ed25519: passkey-key-wire's form for those
 * two key types, held here to its members and their spellings alone (each coordinate 32 bytes in its
 * one base64url form, so its size is fixed). Each reader reads it through passkey-key-wire, where a
 * value of no passkey's form (a curve not its key type's, an EC key with no y) has no thumbprint. No
 * RSA key approves one.
 */
const approverKey = z
	.object({
		kty: z.enum(["EC", "OKP"]),
		crv: z.enum(["P-256", "Ed25519"]),
		x: bytes32,
		y: bytes32.optional(),
	})
	.strict();

/** A creation's items: what a `create()` is for, the account it shows and the evidence it rests on. */
export const items = z
	.object({
		/** The identifier, masked, for display alone; a subject with none (F1's) is named by `user_name`. */
		account: z.string().optional(),
		/** What the evidence is: the first key's mail, an approved `passkey-add`, or a T read before signing up. */
		basis: z.enum(["first-key", "passkey-add", "sign-up"]).optional(),
		/** The evidence's value the screen computes for itself, by its basis. */
		evidence: z.string().min(1),
		/** The sealed mail request's ciphertext hash, as the Core opened it: the first key's path's alone. */
		ct_hash: z.string().min(1).optional(),
		subject: z.string().min(1),
		/** The key generation of the subject this creation is signed for (reset and erasure boundaries count it), bound in the signed bytes. */
		kg: z.number().int().nonnegative(),
		/**
		 * The key whose approval of the passkey-add this creation goes on from (V30): the record's parent,
		 * the screen's own key. Required for a passkey-add, absent for any other basis (the refine below).
		 */
		approver_key: approverKey.optional(),
		options: z
			.object({
				user_id: z.string().min(1),
				user_name: userName.optional(),
				rp_id: z.string().min(1),
				exclude_credentials: z.array(z.string()).max(15),
				/** The algorithms the ceremony offered, as COSE numbers them: those the new key may be of. */
				algorithms: z
					.array(passkeyAlgorithm)
					.min(1)
					.refine((list) => list.every((alg, at) => list.indexOf(alg) === at)),
			})
			.strict(),
	})
	.strict()
	.refine((c) => (c.basis === undefined || c.basis === "first-key") === (c.ct_hash !== undefined), {
		message: "a ciphertext hash is the first key's path's alone",
	})
	.refine(
		(c) =>
			(c.account === undefined) !== (c.options.user_name === undefined) &&
			(c.basis === "sign-up" ? c.options.user_name !== undefined : true) &&
			(c.basis === undefined || c.basis === "first-key" ? c.account !== undefined : true),
		{
			message:
				"a creation names its account by one of account or user_name: the first key's path by account, sign-up's by user_name, passkey-add's by either",
		},
	)
	.refine((c) => (c.approver_key !== undefined) === (c.basis === "passkey-add"), {
		message: "an approving key is passkey-add's alone, and every passkey-add's names one",
	});
