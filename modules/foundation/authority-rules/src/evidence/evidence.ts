import { challengeInput, payloads, typs } from "@mod/sdk-core-wire";
import { type Preimage, recordKinds, schemas } from "@mod/transparency-wire";
import { z } from "zod";

/** The verification the caller does, for the rules to read evidence without crypto of their own. */
export interface Checks {
	/** A compact JWS verified with one of the keys: its header and payload as read, or none. */
	verifyJws(
		jws: string,
		keys: readonly unknown[],
	): { readonly header: unknown; readonly payload: unknown } | undefined;
	/** A WebAuthn assertion verified with the public key, for the challenge and origin: its credential, or none. */
	verifyAssertion(
		assertion: string,
		publicKey: string,
		challenge: string,
		origin: string,
	): { readonly credential: string } | undefined;
	/** SHA-256 of the text's UTF-8 bytes, or of the bytes, base64url without padding. */
	digest(data: string | Uint8Array): string;
}

/** The times the rules hold records to, in milliseconds (a configuration version's). */
export interface RuleTimes {
	/** L: a code's lifetime from its approval's acceptance. */
	readonly codeLifetime: number;
	/** A family's lifetime from its acceptance (the delegation's expiry). */
	readonly refreshLifetime: number;
	/** W_iss: from a start's acceptance to its bundle's. */
	readonly issueWindow: number;
	/** ε: the most two shards' clocks differ by. */
	readonly epsilon: number;
	/** P: how long a new version takes to reach every Core replica. */
	readonly propagation: number;
	/** T_retry: how long a temporary failure is waited out before the record is held. */
	readonly retry: number;
}

/** What a record is read against beside its flow: the ring of its writer's Core generation, the passkeys' origin, the limits. */
export interface Context {
	/** RingKey(Gen(w)): the public keys of the Core ring of the generation that wrote the record. */
	readonly ring: readonly unknown[];
	readonly origin: string;
	readonly limits: RuleTimes;
}

const id = z.string().min(1);
const empty = z.object({}).strict();
/** How a start or a bundle roots: an approval's code, or a family's refresh at its rotation. */
const via = z.discriminatedUnion("via", [
	z.object({ via: z.literal("code") }).strict(),
	z.object({ via: z.literal("refresh"), rotation: z.number().int().nonnegative() }).strict(),
]);

/** A Core writer's preimage `content`, by kind: what transparency-wire leaves to these rules. */
export const contents = Object.freeze({
	approval: empty,
	/**
	 * A first-trust key (the first-key path, F1): its credential and its public key, the uncompressed
	 * P-256 point base64url; the key generation is the signed creation's (`kg`).
	 */
	keyChange: z.object({ variant: z.literal("first"), credential: id, publicKey: id }).strict(),
	start: via,
	bundle: via,
	noEffect: empty,
	abandonment: empty,
});

export type CoreKind = (typeof recordKinds.core)[number];
export type Content<K extends CoreKind> = z.infer<(typeof contents)[K]>;
export const coreKinds: readonly string[] = recordKinds.core;
export const isCoreKind = (kind: string): kind is CoreKind => coreKinds.includes(kind);

/** A Core writer's preimage as read: the wire's form, then its kind's content. */
export type Opened<K extends CoreKind> = {
	readonly preimage: Preimage;
	readonly content: Content<K>;
};

/** Reads an opened preimage: an error names the wire's form (`preimage`) or the kind's content (`content`) that does not hold. */
export function readPreimage<K extends CoreKind>(
	kind: K,
	value: unknown,
): Opened<K> | { readonly error: "preimage" | "content" } {
	const preimage = schemas.preimage.safeParse(value);
	if (!preimage.success) return { error: "preimage" };
	const schema: z.ZodType = contents[kind];
	const content = schema.safeParse(preimage.data.content);
	return content.success
		? { preimage: preimage.data, content: content.data as Content<K> }
		: { error: "content" };
}

type Form = Preimage["evidence"][number]["form"];
/** The values of one form the preimage carries. */
export const evidenceOf = (preimage: Preimage, form: Form) =>
	preimage.evidence.filter((e) => e.form === form).map((e) => e.value);

/** The one value of a form, none where the preimage carries none or several. */
export function oneOf(preimage: Preimage, form: Form): string | undefined {
	const values = evidenceOf(preimage, form);
	return values.length === 1 ? values[0] : undefined;
}

/** A statement signed by the writer generation's ring as a statement, read to its schema; none otherwise. */
export function statementOf<T>(
	jws: string,
	schema: z.ZodType<T>,
	checks: Checks,
	context: Context,
): T | undefined {
	const verified = checks.verifyJws(jws, context.ring);
	if (!verified) return undefined;
	const header = z.object({ typ: z.literal(typs.statement) }).safeParse(verified.header);
	const payload = schema.safeParse(verified.payload);
	return header.success && payload.success ? payload.data : undefined;
}

/** The statement T of an authorization, or of a key's creation or possession. */
export const statements = Object.freeze({
	authorization: payloads.statement,
	creation: payloads.creation,
	possession: payloads.possession,
});

/** Whether a passkey assertion is the key's (its credential and public key) over the statement, for the origin. */
export function assertedBy(
	assertion: string,
	key: { readonly credential: string; readonly publicKey: string },
	statement: string,
	checks: Checks,
	context: Context,
): boolean {
	const challenge = checks.digest(challengeInput(statement, "get"));
	const made = checks.verifyAssertion(assertion, key.publicKey, challenge, context.origin);
	return made?.credential === key.credential;
}

/** A public key's uncompressed P-256 point (0x04, x, y: 65 bytes) from its base64url, none for any other. */
export function pointOf(publicKey: string): Uint8Array | undefined {
	if (!/^[A-Za-z0-9_-]+$/.test(publicKey)) return undefined;
	const bytes = Buffer.from(publicKey, "base64url");
	return bytes.length === 65 && bytes[0] === 4 ? new Uint8Array(bytes) : undefined;
}

/** Whether a statement's times hold the acceptance time: iat ≤ a ≤ exp (the statement in seconds, a in ms). */
export const within = (statement: { readonly iat: number; readonly exp: number }, at: number) =>
	statement.iat * 1000 <= at && at <= statement.exp * 1000;
