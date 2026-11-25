import { z } from "zod";
import {
	approved,
	bytes32,
	compactJws,
	id,
	keyJkt,
	label,
	purposes,
	setSignedText,
	times,
	v,
} from "../primitives.ts";

/** A padded completion's lengths, smallest first. */
const buckets = Object.freeze([16_384, 45_056] as const);
/** The longest credential ID, in bytes, whose completion goes in the smaller bucket. */
const usualIdBytes = 128;

const keyRow = z
	.object({
		credential_id: id,
		label,
		/** When the key was added, in seconds since the epoch: a JWT's NumericDate, as `iat` and `exp`. */
		created_at: z.number().int().nonnegative(),
	})
	.strict();
/** The completions the Core seals to the screen beside the authorization's: passkey-add's, passkey-manage's and a key change. */
export const completions = Object.freeze({
	passkeyAdd: z
		.object({
			...approved,
			purpose: z.literal(purposes.passkeyAdd),
			creation: compactJws,
			...times,
		})
		.strict(),
	passkeyManage: z
		.object({
			...approved,
			purpose: z.literal(purposes.passkeyManage),
			keys: z
				.array(keyRow)
				.max(16)
				.refine((rows) =>
					rows.every(
						(row, at) => rows.findIndex((r) => r.credential_id === row.credential_id) === at,
					),
				),
			/**
			 * What the list answers, where it answers a continuation: a rename's, or a delete's the Core
			 * did not take, its reason sealed with it (`last`: no key would be left; `used`: this approval
			 * deleted one already; `unknown`: no active key of the person's by that id).
			 */
			continued: z
				.discriminatedUnion("stage", [
					z
						.object({
							stage: z.literal("rename"),
							seq: z.number().int().min(1).max(16),
							body_hash: bytes32,
						})
						.strict(),
					z
						.object({
							stage: z.literal("delete"),
							seq: z.number().int().min(1).max(16),
							body_hash: bytes32,
							refused: z.enum(["last", "used", "unknown"]),
						})
						.strict(),
				])
				.optional(),
			...times,
		})
		.strict(),
	keyChange: z
		.object({
			v,
			iss: id,
			purpose: z.enum(["first-key", purposes.passkeyAdd, purposes.passkeyManage, "sign-up"]),
			change: z.discriminatedUnion("op", [
				z.object({ op: z.literal("add"), credential_id: id, key_jkt: keyJkt }).strict(),
				z.object({ op: z.literal("delete"), credential_id: id }).strict(),
			]),
			receipt: compactJws.optional(),
			status: setSignedText.optional(),
			stateOf: setSignedText.optional(),
			...times,
		})
		.strict()
		.refine((c) => (c.change.op === "add") === (c.purpose !== purposes.passkeyManage)),
});

/** How a passkey-add's or passkey-manage's completion is padded before it is sealed, and read back. */
export const padding = Object.freeze({
	/** The lengths a passkey-add's or passkey-manage's completion (a delete's too) is padded to before sealing. */
	buckets,
	/** The bounds each completion fits its bucket within at L0 (ASCII characters, RSA bits), for the sealing side's boot. */
	limits: Object.freeze({ issuerChars: 256, kidChars: 128, rsaBits: 8192 }),
	/**
	 * Its compact JWS padded to the bucket the person's longest credential ID (bytes; a delete taken, its list before it; one not, the list it carries) chooses,
	 * the smaller where 128 or less, so it tells no count, label or key deleted; none where it does not fit.
	 */
	padded: (jws: string, longestIdBytes: number): string | undefined => {
		const bucket = longestIdBytes > usualIdBytes ? buckets[1] : buckets[0];
		return !Number.isSafeInteger(longestIdBytes) ||
			longestIdBytes < 0 ||
			jws.length > bucket ||
			!compactJws.safeParse(jws).success
			? undefined
			: `${jws}${" ".repeat(bucket - jws.length)}`;
	},
	/** An opened completion: a bucket's length, a compact JWS then spaces alone; none otherwise. */
	unpadded: (text: string): string | undefined => {
		if (!(buckets as readonly number[]).includes(text.length)) return undefined;
		const jws = text.trimEnd();
		return compactJws.safeParse(jws).success && /^ *$/.test(text.slice(jws.length))
			? jws
			: undefined;
	},
});
