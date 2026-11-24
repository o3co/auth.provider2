import { createHash } from "node:crypto";
import { z } from "zod";
import type { StoredCode } from "./store/store.ts";

/** What a code keeps from its issuing to its end. */
export interface CodeRecord {
	/** The record's format: this writes and reads 1 alone. */
	readonly format: 1;
	readonly state: "issued" | "consumed";
	readonly clientId: string;
	readonly redirectUri: string;
	readonly challenge: string;
	readonly nonce?: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	readonly session: string;
	readonly subject: string;
	readonly acr?: string;
	/** Set once, after the code is made: a code without one is never redeemed. */
	readonly root?: string;
	readonly binding?: {
		readonly member: string;
		readonly confirmation: string;
		readonly tokenType: string;
	};
	readonly amr: readonly string[];
	readonly authenticatedAt: number;
	readonly authenticatedAtUnknown?: true;
	/** What its approval gives an ID token, where the scope has `openid`. */
	readonly approval?: {
		readonly esig: string;
		readonly apr: { readonly shard: string; readonly n: number };
		readonly approvedAt: number;
	};
	/** Marked when the code came again: the redemption that used it up reads it after issuing. */
	readonly void?: true;
}

const recordShape = z.strictObject({
	format: z.literal(1),
	state: z.enum(["issued", "consumed"]),
	clientId: z.string(),
	redirectUri: z.string(),
	challenge: z.string(),
	nonce: z.string().optional(),
	scope: z.array(z.string()),
	audience: z.array(z.string()),
	session: z.string(),
	subject: z.string(),
	acr: z.string().optional(),
	root: z.string().optional(),
	binding: z
		.strictObject({ member: z.string(), confirmation: z.string(), tokenType: z.string() })
		.optional(),
	amr: z.array(z.string()),
	authenticatedAt: z.number(),
	authenticatedAtUnknown: z.literal(true).optional(),
	approval: z
		.strictObject({
			esig: z.string(),
			apr: z.strictObject({ shard: z.string(), n: z.number() }),
			approvedAt: z.number(),
		})
		.optional(),
	void: z.literal(true).optional(),
});

/** A record as the store keeps it; only code-grant reads what it holds. */
export const toStored = (record: CodeRecord) => record as unknown as StoredCode;
/** A stored value's record, checked on every read; nothing for an unknown format, state or shape. */
export const fromStored = (stored: StoredCode): CodeRecord | undefined => {
	const read = recordShape.safeParse(stored);
	return read.success ? (read.data as CodeRecord) : undefined;
};

export const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** A code's digest: its SHA-256 in base64url, as a challenge is made of a verifier. */
export const digestOf = s256;

/** RFC 7636: a verifier is 43 to 128 unreserved characters. */
export const verifierShape = /^[A-Za-z0-9._~-]{43,128}$/;
