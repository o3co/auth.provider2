import { z } from "zod";
import { canonical, unique } from "../text/text.ts";
import { flows, frames, recordKinds, speaks } from "../words/words.ts";

/**
 * Why the log refuses an append; it refuses with one word and writes nothing. On an unconditional
 * flow: `abandoned`, a stage of an op whose abandonment it accepted (never placed, now or later);
 * `evidenceUsed`, a client's start naming an evidence element (`elements`) a start of that flow
 * named. Their order: the same id and content's original receipt, `sameIdOther`, `abandoned`,
 * `evidenceUsed`; every log keeps both marks without end.
 */
export const appendRefusals = Object.freeze([
	"prevMismatch",
	"sameIdOther",
	"temporary",
	"stopped",
	"lateBundle",
	"keyNotInSet",
	"holdLimit",
	"kindNotAllowed",
	"credInvalid",
	"generationFlowInvalid",
	"abandoned",
	"evidenceUsed",
] as const);

export const coreKinds: readonly string[] = recordKinds.core;
const unconditional: readonly string[] = flows.unconditional;
const roleOf = (kind: string) =>
	(Object.keys(recordKinds) as (keyof typeof recordKinds)[]).find((role) =>
		(recordKinds[role] as readonly string[]).includes(kind),
	);

/** The op ids the log, the Core and the monitor each derive the same way. */
export const opIds = Object.freeze({
	/** A stop instruction's: by the generation it names, so a second one for it is not a new op. */
	stop: (generation: number) => `stop:${generation}`,
	/** An abandonment record's: by the op it abandons and its attempt, from 1. */
	abandonment: (op: string, attempt: number) => `abandonment:${attempt}:${op}`,
	/** A reset boundary's: by its instruction's id, so the same instruction sent again is not a new op. */
	reset: (id: string) => `reset:${id}`,
});

export const v = z.literal(speaks[0]);
export const id = z.string().min(1);
/**
 * A record's id, as its log gives it: never `__proto__`, as a flow's state names its items by it and
 * a store refuses that key, so a log naming one is told apart here, at the boundary.
 */
export const recordId = id.refine((x) => x !== "__proto__", {
	message: "a record's id is never __proto__",
});
export const count = z.number().int().nonnegative();
export const ordinal = z.number().int().positive();
/** SHA-256, base64url without padding. */
export const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/);
export const flow = z.object({ of: z.enum(flows.units), id }).strict();
export const ecKey = z
	.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: base64url, y: base64url })
	.strict();
export const keyed = <K extends z.ZodType>(key: K) => z.object({ kid: id, key }).strict();

/** The suite a Core writer seals a preimage to a monitor key with, as RFC 9180 names it, its info and additional data. */
export const sealing = Object.freeze({
	kem: "DHKEM(P-256, HKDF-SHA256)",
	kdf: "HKDF-SHA256",
	aead: "AES-128-GCM",
	info: "auth.provider2/preimage/v1",
	aad: (on: z.infer<typeof flow>, op: string, stage: number) =>
		canonical({ flow: { of: on.of, id: on.id }, op, stage }),
});

/** Who wrote a record: a Core writer as its credential names it, a key's holder, or the log. */
export const writer = z.discriminatedUnion("role", [
	z.object({ role: z.literal("core"), instance: id, image: id, generation: ordinal }).strict(),
	z.object({ role: z.literal("monitor"), key: id }).strict(),
	z.object({ role: z.literal("publisher"), key: id }).strict(),
	z.object({ role: z.literal("human"), keys: z.array(id).min(1) }).strict(),
	z.object({ role: z.literal("log") }).strict(),
]);

const tokenDigests = z
	.array(z.object({ frame: z.enum(frames), digest }).strict())
	.min(1)
	.refine((list) => unique(list, (t) => t.frame), { message: "a frame is named twice" });
/** What an approval's receipt binds: the digests of the statement, its assertion and the code. */
export const approvalDigests = z
	.object({ statement: digest, assertion: digest, code: digest })
	.strict();
/** What a key change's receipt binds: its statement's digest (the possession, or the passkey-manage statement) and its evidence's (the new key's assertion, or the continuation's body). */
export const keyChangeDigests = z.object({ statement: digest, evidence: digest }).strict();
/** An abandonment record's: the op it abandons, its attempt, and that op's plaintext digest. */
const abandons = z.object({ op: id, attempt: ordinal, digest }).strict();

/** The fields a writer names, in the request and the record alike. */
const named = {
	v,
	kind: z.enum([
		...recordKinds.core,
		...recordKinds.monitor,
		...recordKinds.publisher,
		...recordKinds.human,
	]),
	flow,
	op: id,
	stage: ordinal,
	/** Whether this is the op's last stage. */
	last: z.boolean(),
	registryVersion: ordinal.optional(),
	configVersion: ordinal.optional(),
	/** A Core writer's: its preimage's digest. Another writer's signed JWS: its payload bytes' SHA-256 (people's keys' encoding is not yet decided). */
	plaintextDigest: digest,
	/** The signed body of a record no Core writer writes: a JWS, compact or JSON; people's keys' encoding is not yet decided. */
	signed: z.string().min(1).optional(),
	tokens: tokenDigests.optional(),
	approval: approvalDigests.optional(),
	keyChange: keyChangeDigests.optional(),
	abandons: abandons.optional(),
	/** A client's start: the SHA-256 of each evidence element's JWS signing input, the log's use-once index. */
	elements: z
		.array(digest)
		.min(1)
		.refine((list) => unique(list, (e) => e), { message: "an element is named twice" })
		.optional(),
};

type Named = {
	kind: string;
	flow: { of: string };
	op: string;
	stage: number;
	last: boolean;
	elements?: unknown;
	tokens?: unknown;
	approval?: unknown;
	keyChange?: unknown;
	abandons?: z.infer<typeof abandons> | undefined;
};
/** The rules a request and a record share, on the kind and the fields it holds. */
const kindRules = (r: Named, ctx: z.RefinementCtx) => {
	const fail = (message: string) => ctx.addIssue({ code: "custom", message });
	if ((r.tokens !== undefined) !== (r.kind === "bundle"))
		fail("token digests go with a bundle alone");
	if (r.approval !== undefined && r.kind !== "approval")
		fail("approval digests go with an approval");
	if (r.keyChange !== undefined && r.kind !== "keyChange")
		fail("key change digests go with a key change");
	if ((r.abandons !== undefined) !== (r.kind === "abandonment"))
		fail("abandons goes with an abandonment");
	if (r.elements !== undefined && !(r.kind === "start" && r.flow.of === "client"))
		fail("evidence elements go with a client's start alone");
	// The ops a Core writer may not take: a reset's and a stop's (its op held first would block them),
	// and an abandonment's but for an abandonment.
	if (coreKinds.includes(r.kind) && /^(reset|stop):/.test(r.op))
		fail("a Core writer's op id is never a reset's or a stop's");
	if (r.op.startsWith("abandonment:") && r.kind !== "abandonment")
		fail("an abandonment's op id goes with an abandonment alone");
	if (r.kind === "resetBoundary" && !(r.flow.of === "subject" && r.stage === 1 && r.last === true))
		fail("a reset boundary is a subject's flow's, in one last stage");
	if (r.abandons && r.op !== opIds.abandonment(r.abandons.op, r.abandons.attempt)) {
		fail("an abandonment's op id is derived from the op it abandons and its attempt");
	}
};

/** A Core writer's preimage, sealed to each monitor key `key` of the set (HPKE: `enc` and the ciphertext, base64url). */
const sealed = z
	.array(z.object({ key: id, enc: base64url, ciphertext: base64url }).strict())
	.min(1)
	.refine((list) => unique(list, (s) => s.key), { message: "a monitor key is named twice" });

export const appendRequest = z
	.object({ ...named, prev: count.optional(), preimage: sealed.optional() })
	.strict()
	.superRefine((r, ctx) => {
		kindRules(r, ctx);
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		if ((r.prev === undefined) !== unconditional.includes(r.flow.of)) {
			fail("a conditional flow's append names its previous position, an unconditional one's none");
		}
		const core = coreKinds.includes(r.kind);
		if ((r.preimage !== undefined) !== core)
			fail("a Core writer's record alone carries a sealed preimage");
		if ((r.signed !== undefined) === core)
			fail("a record no Core writer writes carries its signed body");
	});

const placed = {
	id: recordId,
	writer,
	position: ordinal,
	shard: id,
	n: ordinal,
	/** Milliseconds since the epoch, by the shard's clock at the commit. */
	acceptedAt: count,
};

export const written = z
	.object({
		...named,
		...placed,
		/** On a Core writer's record: each monitor key its preimage is sealed to with that ciphertext's hash, and the key set's version the log checked them against. */
		sealedTo: z
			.array(z.object({ key: id, ciphertextHash: digest }).strict())
			.min(1)
			.refine((list) => unique(list, (s) => s.key), { message: "a monitor key is named twice" })
			.optional(),
		keySetVersion: ordinal.optional(),
	})
	.strict()
	.superRefine((r, ctx) => {
		kindRules(r, ctx);
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		if (roleOf(r.kind) !== r.writer.role) fail("the writer's role does not write this kind");
		const sealedFields = [r.sealedTo, r.keySetVersion];
		const core = coreKinds.includes(r.kind);
		if (sealedFields.some((f) => (f === undefined) === core))
			fail("a Core writer's record alone names its sealing");
		if ((r.signed !== undefined) === core)
			fail("a record no Core writer writes carries its signed body");
		if (r.flow.of === "monitor" && r.flow.id !== r.shard) fail("a monitor flow's id is its shard");
	});
const tick = z
	.object({
		v,
		id: recordId,
		writer: z.object({ role: z.literal("log") }).strict(),
		kind: z.literal("tick"),
		shard: id,
		n: ordinal,
		acceptedAt: count,
	})
	.strict();
export const record = z.union([written, tick]);

export const keySet = z
	.object({
		v,
		version: ordinal,
		keys: z
			.array(keyed(ecKey))
			.min(1)
			.refine((k) => unique(k, (x) => x.kid), { message: "a kid is named twice" }),
	})
	.strict();

export const appendAnswer = z.discriminatedUnion("result", [
	z
		.object({
			v,
			result: z.literal("accepted"),
			id: recordId,
			position: ordinal,
			shard: id,
			n: ordinal,
			acceptedAt: count,
			/** The receipts, as compact JWS: one per token in the request's order, or one for a record of none. */
			receipts: z.array(z.string().regex(/^[\w-]+\.[\w-]+\.[\w-]+$/)).min(1),
		})
		.strict(),
	z
		.object({
			v,
			result: z.literal("refused"),
			refusal: z.enum(appendRefusals),
			keySet: keySet.optional(),
		})
		.strict()
		.refine((a) => a.keySet === undefined || a.refusal === "keyNotInSet", {
			message: "the shard's key set goes with keyNotInSet alone",
		}),
]);

export const recordRef = z.object({ shard: id, n: ordinal }).strict();

export const preimage = z
	.object({
		v,
		/** The record the chain roots in, and the record it is the next link of. */
		root: id.optional(),
		parent: id.optional(),
		evidence: z.array(
			z
				.object({
					form: z.enum([
						"statement",
						"assertion",
						"jar",
						"dpopProof",
						"clientAssertion",
						"token",
						"continuation",
						"completion",
					]),
					value: z.string().min(1),
				})
				.strict(),
		),
		/** The kind's content, held to `authority-rules`' schema, not here. */
		content: z.record(z.string(), z.unknown()),
	})
	.strict();

export type AppendRequest = z.infer<typeof appendRequest>;
export type AppendAnswer = z.infer<typeof appendAnswer>;
export type LogRecord = z.infer<typeof record>;
export type Preimage = z.infer<typeof preimage>;
export type RecordRef = z.infer<typeof recordRef>;
export type Writer = z.infer<typeof writer>;
export type Flow = z.infer<typeof flow>;
