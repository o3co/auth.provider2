import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import { payloads, typs, versions } from "@mod/sdk-core-wire";
import { z } from "zod";
import type { Completed, ItemsOf, Purpose, StoredStatement } from "../contract.ts";

/** The wire version this Core writes: the latest `sdk-core-wire` speaks. */
export const wireVersion = versions[versions.length - 1] as (typeof versions)[number];

export const sha256 = (data: string) => createHash("sha256").update(data).digest("base64url");

const id = z.string().min(1);
/** A statement's record: what it was signed as, and how far it went. */
const recordShape = z
	.object({
		purpose: z.enum(["authorization", "passkey-add", "passkey-manage", "creation", "possession"]),
		jws: id,
		sid: id,
		/** Its expiry, in ms. */
		exp: z.number(),
		e_enc: id,
		e_sig: payloads.statement.shape.e_sig,
		state: z.enum(["issued", "used", "completed"]),
		/** A T's: the stages its owner allowed at its issue; its sign-up once begun (F1). */
		continues: z.array(z.literal("sign-up")).min(1).optional(),
		signUp: z.object({ subject: id.optional(), credential: id.optional() }).strict().optional(),
		subject: id.optional(),
		credential: id.optional(),
		/** The id of the asserting key's registration's record on the subject's flow. */
		registration: id.optional(),
		verification: id.optional(),
		/** When it was used, by the kernel's clock, in ms. */
		usedAt: z.number().optional(),
		/** The assertion's JSON text that used it, as received, kept for its approval's record on the flow. */
		assertion: id.optional(),
		/** The last continuation taken: its sequence number and body's hash; as sent, its body (UTF-8 text) and `r‖s`. */
		seq: z.number().int().nonnegative(),
		body: id.optional(),
		sent: z.object({ body: z.string(), signature: id }).strict().optional(),
		/** A sealed continuation's: E_sig's signature, kept with its number; its opened body never is. */
		sig: id.optional(),
		/** A delete's: the longest credential ID's bytes among the subject's keys when its number was taken. */
		pad: z.number().int().nonnegative().optional(),
		/** The call that holds the last continuation's step, and until when (kernel clock, ms). */
		claimed: z.object({ by: id, until: z.number() }).strict().optional(),
		/** What the step of the last continuation answered, once it did. */
		result: z.json().optional(),
		enc: id.optional(),
		/** The digest of the code its completion carries. */
		code: id.optional(),
		/** The path's purpose a possession's key-change completion was asked for. */
		asked: z.enum(["first-key", "passkey-add", "sign-up"]).optional(),
		/** The id of the approval's record on the subject's flow, which the code's chain roots in. */
		record: id.optional(),
		/** That record's reference on the log, its shard and number. */
		ref: z.object({ shard: id, n: z.number().int().positive() }).strict().optional(),
		/** When the log accepted that record, in ms. */
		acceptedAt: z.number().optional(),
		/** Set once its caller let the completion go out: `completionOf` gives none before. */
		published: z.literal(true).optional(),
		ct: id.optional(),
	})
	.strict();
export type StatementRecord = z.output<typeof recordShape>;
/** The record read; a record of another shape is a store that cannot tell, so unavailable. */
export const recordOf = (kept: StoredStatement | undefined): StatementRecord | undefined => {
	if (kept === undefined) return undefined;
	const read = recordShape.safeParse(kept);
	if (!read.success) throw new Unavailable("approvals");
	return read.data;
};
/** The completion a record keeps, where it keeps one whole; none otherwise. */
export const completionIn = (r: StatementRecord): Kept | undefined =>
	r.enc && r.ct && r.record && r.ref && r.acceptedAt !== undefined
		? {
				kind: "completed",
				enc: r.enc,
				ct: r.ct,
				record: r.record,
				ref: r.ref,
				acceptedAt: r.acceptedAt,
			}
		: undefined;
type Kept = Extract<Completed, { kind: "completed" }>;
export const stored = (r: StatementRecord) => r as unknown as StoredStatement;

/** The purposes a key's management approves: no items, used by an assertion. */
export const itemless = (purpose: Purpose) =>
	purpose === "passkey-add" || purpose === "passkey-manage";

/** The items a statement's payload carries, under its purpose's member. */
export const itemsIn = (jws: string, purpose: Purpose): ItemsOf[Purpose] => {
	const payload = JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));
	if (itemless(purpose)) return {};
	return payload[purpose === "authorization" ? "approval" : purpose];
};

/** The use-once mark of a statement in the flow state, as `authority-rules`' fold names it. */
export const statementMark = (sid: string) => `statement:${sid}`;

/** How long a statement's record outlives the statement, in seconds. */
export const keptPastS = 60;
export const recordEnd = (r: StatementRecord) => r.exp + keptPastS * 1000;

/** The creation a sign-up's step answered, kept as its result; none for a refusal or no answer. */
export const creationIn = (result: StatementRecord["result"]): string | undefined => {
	const read = z.object({ creation: id }).strict().safeParse(result);
	return read.success ? read.data.creation : undefined;
};

/** When a statement was issued, in ms, as its signed `iat` says. */
export const issuedAtOf = (jws: string): number =>
	(
		JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8")) as {
			iat: number;
		}
	).iat * 1000;

/** Whether the statement verifies by the Core's ring of the generation this Core signs as. */
export const current = async (keys: Pick<Keys, "verify">, jws: string) =>
	(await keys.verify("core", jws, typs.statement)).kind === "valid";
