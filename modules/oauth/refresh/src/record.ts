import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { z } from "zod";
import type { FamilyRecords, StoredFamilyRecord } from "./store.ts";

const id = z.string().min(1);
const binding = z.strictObject({ member: id, confirmation: id, tokenType: id });

/**
 * A family, by the id of the bundle record that founded it: what its root does not tell (proposal
 * 3.9) and what it was founded with. Its root: the statement as signed, the assertion as received,
 * the credential, its registration's record and public key, and the Core generation that signed it.
 */
const familyShape = z.strictObject({
	format: z.literal(1),
	subject: id,
	client: id,
	session: id,
	scope: z.array(id),
	audience: z.array(id),
	amr: z.array(id),
	acr: id.optional(),
	/** When its approval's record was accepted, in ms: its tokens' authentication time. */
	authTime: z.number(),
	/** Its delegation's end, in ms: its statement's issue and the delegation's length (O27). */
	end: z.number(),
	binding,
	statement: id,
	assertion: id,
	credential: id,
	registration: id,
	publicKey: id,
	generation: z.number().int(),
	/** The SHA-256 of its refresh token's secret. */
	secret: id,
	/** The digest of the code whose redemption founded it. */
	code: id,
	revoked: z.literal(true).optional(),
});
export type FamilyRecord = z.output<typeof familyShape>;

/** The family a key is bound to (Q27): one live family a key. */
const keyShape = z.strictObject({ format: z.literal(1), subject: id, family: id });
/** What a code's redemption founded, or that none may be founded from it (its code voided first). */
const codeShape = z.strictObject({
	format: z.literal(1),
	subject: id,
	family: id.optional(),
	revoked: z.literal(true).optional(),
});

/** Each record's name, by its kind. */
export const nameOf = {
	family: (family: string) => `f.${family}`,
	key: (confirmation: string) => `k.${confirmation}`,
	code: (code: string) => `c.${code}`,
};

const opened = <T>(shape: z.ZodType<T>, kept: StoredFamilyRecord | undefined): T | undefined => {
	if (kept === undefined) return undefined;
	const read = shape.safeParse(kept);
	// A record of another shape is one the place cannot tell: unavailable, never taken for none.
	if (!read.success) throw new Unavailable("refresh: a record it cannot read");
	return read.data;
};
const stored = (value: object) => value as unknown as StoredFamilyRecord;

export const read = {
	family: (kept: StoredFamilyRecord | undefined) => opened(familyShape, kept),
	key: (kept: StoredFamilyRecord | undefined) => opened(keyShape, kept),
	code: (kept: StoredFamilyRecord | undefined) => opened(codeShape, kept),
};
export const write = {
	family: (r: FamilyRecord) => stored(r),
	key: (family: string, subject: string) => stored({ format: 1, subject, family }),
	code: (r: z.output<typeof codeShape>) => stored(r),
};

export const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");

/** A refresh token: its family's id and its secret, each base64url, joined by a dot. */
export const tokenOf = (family: string, secret: string) =>
	`${Buffer.from(family).toString("base64url")}.${secret}`;
/** A refresh token's family and secret; none for a token of another shape. */
export function tokenParts(token: string) {
	const [family, secret, more] = token.split(".");
	if (!family || !secret || more !== undefined) return undefined;
	if (!/^[\w-]+$/.test(family) || !/^[\w-]{43}$/.test(secret)) return undefined;
	return { family: Buffer.from(family, "base64url").toString("utf8"), secret };
}

/** Each record's kind and what it was named for, from its name; none for a name of no kind. */
export const kindOf = (name: string) => {
	const kind = (Object.keys(nameOf) as (keyof typeof nameOf)[]).find((k) =>
		name.startsWith(nameOf[k]("")),
	);
	return kind === undefined ? undefined : { kind, of: name.slice(nameOf[kind]("").length) };
};

/** Whether a family is live now: not revoked, before its end. */
export const live = (r: FamilyRecord | undefined, now: number): r is FamilyRecord =>
	r !== undefined && !r.revoked && now < r.end;

/** Ends a family for good, keeping its record to its end; nothing where it is gone. */
export async function revokeFamily(records: FamilyRecords, family: string) {
	await records.change(nameOf.family(family), (kept) => {
		const r = read.family(kept);
		return r && !r.revoked ? { value: write.family({ ...r, revoked: true }) } : undefined;
	});
}

/** A record outlives what it covers by this much, for clock drift between hosts. */
export const allowanceMs = 120_000;
