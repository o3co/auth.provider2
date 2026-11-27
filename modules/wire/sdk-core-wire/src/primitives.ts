import { z } from "zod";

/** The building blocks the package's schemas and its internal modules `completions` and `creation` share. */

/** The wire versions a reader of this protocol speaks; a statement and a completion name one as `v`. */
export const versions = Object.freeze([1] as const);

/** The purposes a statement names. */
export const purposes = Object.freeze({
	authorization: "authorization",
	creation: "creation",
	possession: "possession",
	passkeyAdd: "passkey-add",
	passkeyManage: "passkey-manage",
});

/** 32 bytes in their one unpadded base64url spelling: 43 characters, the last carrying no bit past them. */
export const bytes32 = z.string().regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
/** A SHA-256 thumbprint, base64url. */
export const keyJkt = bytes32;
export const v = z.literal(versions[0]);
export const label = z.string().regex(/^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,64}$/u);
export const compactJws = z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
export const id = z.string().min(1);
export const times = { iat: z.number().int(), exp: z.number().int() };
export const approved = { v, iss: id, t_hash: bytes32, assertion_hash: bytes32 };
/** A set's signed object (a status, a stateOf) as JSON text, which transparency-wire's `setSigned` reads. */
export const setSignedText = z.string().refine((text) => {
	try {
		const value: unknown = JSON.parse(text);
		return value !== null && typeof value === "object" && !Array.isArray(value);
	} catch {
		return false;
	}
});
