import { z } from "zod";

/**
 * The contract of the transparency log, which the log and the monitor hold and the Core's writers,
 * the receivers and their companions follow: the words, the schemas of what each side signs, sends
 * or reads, and the inputs a digest or a sealing covers. Signing, sealing and judging are each
 * side's own.
 */

/** The wire versions a reader of this protocol speaks; every object names one of them as `v`. */
export const speaks = Object.freeze([1] as const);

/** The `typ` of each signed object. */
export const logTyps = Object.freeze({
	receipt: "receipt+jwt",
	judgment: "judgment+jwt",
	checkpoint: "checkpoint+jwt",
	status: "status+jwt",
	/** The reasons of the status's not-accepted ids, for operators, apart from the status. */
	statusReasons: "status-reasons+jwt",
	stateOf: "state-of+jwt",
	keySet: "key-set+jwt",
	confirmation: "confirmation+jwt",
	denial: "denial+jwt",
	erasureBoundary: "erasure-boundary+jwt",
	tombstone: "tombstone+jwt",
	coreRingKey: "core-ring-key+jwt",
	signerSet: "signer-set+jwt",
	/** Signed by people's keys, in an encoding not yet decided: no `+jwt`, as it may be no JWS. */
	stopInstruction: "stop-instruction",
	restartApproval: "restart-approval",
	/** The callback's proof the login screen signs with E_sig (A38). */
	callback: "callback+jwt",
});

/** The record kinds, by the writer role that may write each; a role writes no other kind. */
export const recordKinds = Object.freeze({
	core: Object.freeze([
		"approval",
		"keyChange",
		"start",
		"bundle",
		"noEffect",
		"abandonment",
	] as const),
	monitor: Object.freeze([
		"keySet",
		"confirmation",
		"denial",
		"erasureBoundary",
		"tombstone",
	] as const),
	publisher: Object.freeze([
		"registryVersion",
		"configVersion",
		"coreRingKey",
		"signerSet",
	] as const),
	/** The generation flow's kinds, signed by people's keys. */
	human: Object.freeze(["stopInstruction", "restartApproval"] as const),
	/** The log's empty commit. */
	log: Object.freeze(["tick"] as const),
});

/** What a flow is the flow of; an unconditional flow's append names no previous position. */
export const flows = Object.freeze({
	units: Object.freeze(["subject", "client", "publisher", "generation", "monitor"] as const),
	unconditional: Object.freeze(["client"] as const),
});

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

/** The monitor's four verdicts (A45) and the outcome, a separate axis: whether a stage took effect. */
export const judgments = Object.freeze({
	verdicts: Object.freeze(["verified", "forged", "held", "unsupported"] as const),
	outcomes: Object.freeze(["took", "didNotTake"] as const),
});

/** A shard's generation state, and why an id is not accepted (for operators alone). */
export const statusWords = Object.freeze({
	shardStates: Object.freeze(["running", "stopped"] as const),
	denyReasons: Object.freeze([
		"forged",
		"held",
		"generationStopped",
		"bundleAbandoned",
		"rootDenied",
	] as const),
});

/** The signer sets the generation flow's kinds are held to: how many sign, of at least how many keys. */
export const signers = Object.freeze({
	stopInstruction: Object.freeze({ required: 1, least: 1 }),
	restartApproval: Object.freeze({ required: 2, least: 3 }),
});

/** A canonical JSON text: object keys sorted, undefined members left out, so both sides build the same bytes. */
function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		const keys = Object.keys(record)
			.filter((key) => record[key] !== undefined)
			.sort();
		return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

const coreKinds: readonly string[] = recordKinds.core;
const unconditional: readonly string[] = flows.unconditional;
const roleOf = (kind: string) =>
	(Object.keys(recordKinds) as (keyof typeof recordKinds)[]).find((role) =>
		(recordKinds[role] as readonly string[]).includes(kind),
	);
const unique = <T>(list: readonly T[], key: (item: T) => unknown) =>
	list.every((item, i) => list.findIndex((other) => key(other) === key(item)) === i);

/**
 * A JSON text as read, or why it is refused: not JSON, a key named twice in one object at any depth
 * (keys compared as decoded, escapes and all), or a number past a double.
 */
function readJson(text: string): { readonly value: unknown } | { readonly error: string } {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return { error: "not_json" };
	}
	// The text is JSON: a string is a key where an object's `{` or `,` comes right before it.
	const open: (string[] | undefined)[] = [];
	let before = "";
	for (let i = 0; i < text.length; i++) {
		const c = text.charAt(i);
		if (c === '"') {
			let end = i + 1;
			while (text.charAt(end) !== '"') end += text.charAt(end) === "\\" ? 2 : 1;
			const keys = open[open.length - 1];
			if (keys && (before === "{" || before === ",")) {
				const key = JSON.parse(text.slice(i, end + 1)) as string;
				if (keys.includes(key)) return { error: `duplicate_key:${key}` };
				keys.push(key);
			}
			before = '"';
			i = end;
		} else if (c === "{" || c === "[") {
			open.push(c === "{" ? [] : undefined);
			before = c;
		} else if (c === "}" || c === "]") {
			open.pop();
			before = c;
		} else if (c.trim() !== "") before = c;
	}
	const finite = (x: unknown): boolean =>
		typeof x === "number"
			? Number.isFinite(x)
			: x !== null && typeof x === "object"
				? Object.values(x).every(finite)
				: true;
	return finite(value) ? { value } : { error: "number" };
}

/** The op ids the log, the Core and the monitor each derive the same way. */
export const opIds = Object.freeze({
	/** A stop instruction's: by the generation it names, so a second one for it is not a new op. */
	stop: (generation: number) => `stop:${generation}`,
	/** An abandonment record's: by the op it abandons and its attempt, from 1. */
	abandonment: (op: string, attempt: number) => `abandonment:${attempt}:${op}`,
});

const isObject = (x: unknown): x is Record<string, unknown> =>
	x !== null && typeof x === "object" && !Array.isArray(x);

/** P-256's field prime and its curve's b (a = -3). */
const p256 = Object.freeze({
	p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
	b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
});
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** A 32-byte value from its 43 base64url characters, the last one's two spare bits zero; none for any other. */
function coordinate(text: unknown): bigint | undefined {
	if (typeof text !== "string" || text.length !== 43) return undefined;
	let value = 0n;
	for (const char of text) {
		const at = alphabet.indexOf(char);
		if (at < 0) return undefined;
		value <<= 6n;
		for (let bit = 32, big = 32n; bit >= 1; bit >>= 1, big >>= 1n) if (at & bit) value |= big;
	}
	return (value & 3n) === 0n ? value >> 2n : undefined;
}
const modP = (n: bigint) => ((n % p256.p) + p256.p) % p256.p;
/** Whether the coordinates name a point of P-256: each below the prime, y² = x³ − 3x + b. */
const onP256 = (x: bigint, y: bigint) =>
	x < p256.p && y < p256.p && modP(y * y) === modP(x * x * x - 3n * x + p256.b);

/**
 * The token receipt gate: the claim a token carries its receipt in, the frames, the one JSON
 * reading, what a token's digest covers, the input of an ID token's `esig`, and the words of the
 * receivers' checks (R16–R18).
 */
export const tokens = Object.freeze({
	claim: "txr",
	frames: Object.freeze(["accessToken", "idToken", "family"] as const),
	/** Reads a JSON text, refusing a key named twice at any depth and a number past a double. */
	parse: readJson,
	/**
	 * From a token's header and claims texts, each read by `parse` and an object: the two, the
	 * receipt claim left out, canonically. The digest is this text's SHA-256.
	 */
	digestInput: (
		header: string,
		claims: string,
	): { readonly input: string } | { readonly error: string } => {
		const h = readJson(header);
		const c = readJson(claims);
		if ("error" in h) return h;
		if ("error" in c) return c;
		if (!isObject(h.value) || !isObject(c.value)) return { error: "not_object" };
		return { input: canonicalJson({ header: h.value, claims: { ...c.value, txr: undefined } }) };
	},
	/**
	 * A P-256 key's RFC 7638 thumbprint input (its members sorted, no whitespace), the thumbprint
	 * being this text's SHA-256: `esig`'s. None for a key of other members, kind or curve, or whose x
	 * or y is not 32 bytes in canonical base64url, or is no point of the curve: a key exported with
	 * more members (`kid`, `alg`, `ext`, `key_ops`) is trimmed to these four first.
	 */
	ecThumbprintInput: (jwk: unknown): string | undefined => {
		if (!isObject(jwk) || Object.keys(jwk).sort().join() !== "crv,kty,x,y") return undefined;
		if (jwk.kty !== "EC" || jwk.crv !== "P-256") return undefined;
		const x = coordinate(jwk.x);
		const y = coordinate(jwk.y);
		if (x === undefined || y === undefined || !onP256(x, y)) return undefined;
		return `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
	},
	/**
	 * The receivers' checks: the frames a receipt check (R16, R17) reads, and each check's faults,
	 * the first that holds named. A receipt: none in the token (`noReceipt`); one not signed by the
	 * log or of another shape (`receipt`); its digest not the token's (`digest`); not a bundle's of
	 * the frame (`kind`); another flow (`flow`); older than `maxAge` allows (`tooOld`); its `n` past
	 * the status's W_s (`notYetChecked`: fetch the status again and take nothing until it covers
	 * it); in the not-accepted ids (`denied`); a status not signed by enough of its set
	 * (`status`). A callback: the proof unreadable or unsigned (`proof`); its key's thumbprint not
	 * the ID token's `esig` (`key`); its `apr` not the ID token's (`apr`); `iss`, `client_id`,
	 * `state` or `code_hash` not the expected (`field`). Fetching the status every τ_sdk and keeping
	 * each signer set's newest version are the SDK's.
	 */
	checks: Object.freeze({
		frames: Object.freeze(["idToken", "accessToken"] as const),
		receiptFaults: Object.freeze([
			"noReceipt",
			"receipt",
			"digest",
			"kind",
			"flow",
			"tooOld",
			"notYetChecked",
			"denied",
			"status",
		] as const),
		callbackFaults: Object.freeze(["proof", "key", "apr", "field"] as const),
	}),
});

const v = z.literal(speaks[0]);
const id = z.string().min(1);
const count = z.number().int().nonnegative();
const ordinal = z.number().int().positive();
/** SHA-256, base64url without padding. */
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/);
const flow = z.object({ of: z.enum(flows.units), id }).strict();
const ecKey = z
	.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: base64url, y: base64url })
	.strict();
const publicKey = z
	.object({
		kty: z.enum(["EC", "OKP", "RSA"]),
		crv: z.string().min(1).optional(),
		x: base64url.optional(),
		y: base64url.optional(),
		n: base64url.optional(),
		e: base64url.optional(),
	})
	.strict();
const keyed = <K extends z.ZodType>(key: K) => z.object({ kid: id, key }).strict();
/** A P-256 key held to the thumbprint's form: x and y 32 bytes in canonical base64url, a point of the curve. */
const p256Key = ecKey.refine((key) => tokens.ecThumbprintInput(key) !== undefined, {
	message: "x and y are no point of P-256 in canonical base64url",
});

/** The suite a Core writer seals a preimage to a monitor key with, as RFC 9180 names it, its info and additional data. */
export const sealing = Object.freeze({
	kem: "DHKEM(P-256, HKDF-SHA256)",
	kdf: "HKDF-SHA256",
	aead: "AES-128-GCM",
	info: "auth.provider2/preimage/v1",
	aad: (on: z.infer<typeof flow>, op: string, stage: number) =>
		canonicalJson({ flow: { of: on.of, id: on.id }, op, stage }),
});

/** Who wrote a record: a Core writer as its credential names it, a key's holder, or the log. */
const writer = z.discriminatedUnion("role", [
	z.object({ role: z.literal("core"), instance: id, image: id, generation: ordinal }).strict(),
	z.object({ role: z.literal("monitor"), key: id }).strict(),
	z.object({ role: z.literal("publisher"), key: id }).strict(),
	z.object({ role: z.literal("human"), keys: z.array(id).min(1) }).strict(),
	z.object({ role: z.literal("log") }).strict(),
]);

const tokenDigests = z
	.array(z.object({ frame: z.enum(tokens.frames), digest }).strict())
	.min(1)
	.refine((list) => unique(list, (t) => t.frame), { message: "a frame is named twice" });
/** What an approval's receipt binds: the digests of the statement, its assertion and the code. */
const approvalDigests = z.object({ statement: digest, assertion: digest, code: digest }).strict();
/** What a key change's receipt binds: its statement's digest (the possession, or the passkey-manage statement) and its evidence's (the new key's assertion, or the continuation's body). */
const keyChangeDigests = z.object({ statement: digest, evidence: digest }).strict();
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
	if (r.abandons && r.op !== opIds.abandonment(r.abandons.op, r.abandons.attempt)) {
		fail("an abandonment's op id is derived from the op it abandons and its attempt");
	}
};

/** A Core writer's preimage, sealed to each monitor key `key` of the set (HPKE: `enc` and the ciphertext, base64url). */
const sealed = z
	.array(z.object({ key: id, enc: base64url, ciphertext: base64url }).strict())
	.min(1)
	.refine((list) => unique(list, (s) => s.key), { message: "a monitor key is named twice" });

const appendRequest = z
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
	id,
	writer,
	position: ordinal,
	shard: id,
	n: ordinal,
	/** Milliseconds since the epoch, by the shard's clock at the commit. */
	acceptedAt: count,
};

const written = z
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
		id,
		writer: z.object({ role: z.literal("log") }).strict(),
		kind: z.literal("tick"),
		shard: id,
		n: ordinal,
		acceptedAt: count,
	})
	.strict();
const record = z.union([written, tick]);

const keySet = z
	.object({
		v,
		version: ordinal,
		keys: z
			.array(keyed(ecKey))
			.min(1)
			.refine((k) => unique(k, (x) => x.kid), { message: "a kid is named twice" }),
	})
	.strict();

const appendAnswer = z.discriminatedUnion("result", [
	z
		.object({
			v,
			result: z.literal("accepted"),
			id,
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

const receipt = z
	.object({
		v,
		iss: id,
		id,
		writer,
		kind: z.enum([
			...recordKinds.core,
			...recordKinds.monitor,
			...recordKinds.publisher,
			...recordKinds.human,
		]),
		flow,
		position: ordinal,
		shard: id,
		n: ordinal,
		acceptedAt: count,
		plaintextDigest: digest,
		/** A token's frame and the digest of its header and claims (`tokens.digestInput`). */
		token: z
			.object({ frame: z.enum(tokens.frames), digest })
			.strict()
			.optional(),
		approval: approvalDigests.optional(),
		keyChange: keyChangeDigests.optional(),
	})
	.strict()
	.refine(
		(r) =>
			(r.token !== undefined) === (r.kind === "bundle") &&
			(r.approval === undefined || r.kind === "approval") &&
			(r.keyChange === undefined || r.kind === "keyChange"),
		{
			message:
				"a token goes with a bundle's receipt, approval digests with an approval's, key change digests with a key change's",
		},
	);

/** Room the later stages add to, signed with the rest; a reader ignores a name in it it does not know. */
const ext = z.record(z.string(), z.unknown()).optional();
const verdict = z.enum(judgments.verdicts);
const outcome = z.enum(judgments.outcomes);
const ids = z
	.array(id)
	.refine((list) => unique(list, (x) => x), { message: "an id is named twice" });

const judgment = z
	.object({ v, id, flow, position: ordinal, shard: id, n: ordinal, verdict, outcome })
	.strict();

const checkpoint = z
	.object({
		v,
		shard: id,
		watermark: count,
		deny: ids,
		/** The ids marked to count toward a writer's hold limit (A46). */
		counted: ids,
		/** The forged ids, each with its writer's generation: the generations the log stops on accepting this. */
		forged: z
			.array(z.object({ id, generation: ordinal }).strict())
			.refine((list) => unique(list, (f) => f.id), { message: "an id is named twice" }),
		ext,
	})
	.strict()
	.refine((c) => c.forged.every((f) => c.deny.includes(f.id)), {
		message: "a forged id is among the not-accepted ids",
	});

const shardState = z
	.object({ watermark: count, generation: ordinal, state: z.enum(statusWords.shardStates) })
	.strict();
const status = z
	.object({ v, version: ordinal, shards: z.record(id, shardState), deny: ids, ext })
	.strict();
const statusReasons = z
	.object({
		v,
		version: ordinal,
		reasons: z
			.array(z.object({ id, reason: z.enum(statusWords.denyReasons) }).strict())
			.refine((list) => unique(list, (r) => r.id), { message: "an id is named twice" }),
	})
	.strict();

const stateOf = z
	.object({
		v,
		flow,
		position: count,
		/** The flow's state as the one fold makes it, held to `authority-rules`' schema, not here. */
		state: z.record(z.string(), z.unknown()),
		/** Each position's verdict and outcome, from 1 to `position`, each once and in order. */
		results: z.array(z.object({ position: ordinal, id, verdict, outcome }).strict()),
	})
	.strict()
	.refine(
		(s) => s.results.length === s.position && s.results.every((r, i) => r.position === i + 1),
		{ message: "results go from 1 to the position" },
	);

const recordRef = z.object({ shard: id, n: ordinal }).strict();

const preimage = z
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
						"resetInstruction",
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

const registration = z.object({ v, registration: id }).strict();
/** A body that acts on a flow binds it: the flow, the op and the previous position its envelope names. */
const bound = z.object({ v, flow, op: id, prev: count }).strict();
const stopInstruction = z.object({ v, installation: id, generation: ordinal }).strict();
const restartApproval = z
	.object({
		v,
		installation: id,
		ringKey: digest,
		prev: ordinal.optional(),
		from: ordinal.optional(),
		evidence: digest.optional(),
	})
	.strict()
	.refine(
		(a) => [a.prev, a.from, a.evidence].every((f) => (f === undefined) === (a.from === undefined)),
		{
			message:
				"a restart names its previous position, generation and evidence; the install approval none",
		},
	);
const signerSet = z
	.object({
		v,
		/** Only grows, per purpose: a reader takes no set older than the one it holds. */
		version: ordinal,
		// Every signed object's typ but the callback's proof, which E_sig signs and no set.
		purpose: z.enum(
			Object.keys(logTyps).filter((name) => name !== "callback") as [
				Exclude<keyof typeof logTyps, "callback">,
				...Exclude<keyof typeof logTyps, "callback">[],
			],
		),
		keys: z
			.array(keyed(publicKey))
			.min(1)
			.refine((k) => unique(k, (x) => x.kid), { message: "a kid is named twice" }),
		required: ordinal,
	})
	.strict()
	.refine((s) => s.required <= s.keys.length, { message: "more required than keys" })
	.refine(
		(s) => {
			const held =
				s.purpose === "stopInstruction" || s.purpose === "restartApproval"
					? signers[s.purpose]
					: undefined;
			return !held || (s.required === held.required && s.keys.length >= held.least);
		},
		{ message: "a generation flow's signer set is held to its count" },
	);

const bodies = Object.freeze({
	keySet,
	confirmation: registration,
	denial: registration,
	erasureBoundary: bound,
	tombstone: bound,
	coreRingKey: z.object({ v, kid: id, key: publicKey }).strict(),
	signerSet,
	stopInstruction,
	restartApproval,
});

/** A record no Core writer writes, read with the body its signature verified: the body must match the envelope. */
const signedRecord = z
	.object({ record: written, body: z.unknown() })
	.strict()
	.superRefine(({ record: r, body }, ctx) => {
		const fail = (message: string) => ctx.addIssue({ code: "custom", message });
		if (coreKinds.includes(r.kind)) return fail("a Core writer's record has no signed body");
		const schema = (bodies as Record<string, z.ZodType>)[r.kind];
		if (!schema) return; // a version's body is its own wire's
		const read = schema.safeParse(body);
		if (!read.success) return fail("the body does not read as its kind's");
		const b = read.data as Record<string, unknown>;
		const prev = r.position - 1;
		if (r.kind === "erasureBoundary" || r.kind === "tombstone") {
			const f = b.flow as z.infer<typeof flow>;
			if (f.of !== r.flow.of || f.id !== r.flow.id || b.op !== r.op || b.prev !== prev)
				fail("the body names another flow, op or previous position than its envelope");
		}
		if (r.kind === "stopInstruction" && r.op !== opIds.stop(b.generation as number))
			fail("a stop's op id is derived from the generation it names");
		if (r.kind === "restartApproval" && (b.from === undefined ? r.position !== 1 : b.prev !== prev))
			fail("a restart's body names its previous position; the install approval sits at 1");
	});

/**
 * An object a signer set signs (a status, a checkpoint, a stateOf: KA-18), as RFC 7515's JWS JSON
 * General Serialization: one payload and a signature per signer. Each protected header names `alg`,
 * the object's `typ` and its key's `kid`; a reader verifies each signature with the set's key of that
 * kid and counts the kids that verify against the set's `required`.
 */
const setSigned = z
	.object({
		payload: base64url,
		signatures: z
			.array(z.object({ protected: base64url, signature: base64url }).strict())
			.min(1)
			.refine((list) => unique(list, (s) => s.protected), {
				message: "a protected header is named twice",
			}),
	})
	.strict();

/** The callback's proof (A38): its header, E_sig's public key in it. */
const callbackHeader = z
	.object({ alg: z.literal("ES256"), typ: z.literal(logTyps.callback), jwk: p256Key })
	.strict();
/** Its body: the issuer, the client, the state, the code's whole UTF-8 SHA-256, ⑤'s record, and the device's time in seconds (no freshness rests on it). */
const callbackProof = z
	.object({ iss: id, client_id: id, state: id, code_hash: digest, apr: recordRef, iat: count })
	.strict();
/** An ID token's evidence claims, the two taken out of its claims and read alone: the thumbprint of the approved T's E_sig, and the approval's record. */
const idTokenEvidence = z.object({ esig: digest, apr: recordRef }).strict();

/** The schemas, as each side reads what it received or verified to them. */
export const schemas = Object.freeze({
	appendRequest,
	appendAnswer,
	record,
	receipt,
	judgment,
	checkpoint,
	status,
	statusReasons,
	stateOf,
	preimage,
	recordRef,
	signerSet,
	/** The signed bodies of the records no Core writer writes, each with its `typ`. */
	bodies,
	signedRecord,
	setSigned,
	callbackHeader,
	callbackProof,
	idTokenEvidence,
});

export type AppendRequest = z.infer<typeof appendRequest>;
export type AppendAnswer = z.infer<typeof appendAnswer>;
export type LogRecord = z.infer<typeof record>;
export type Receipt = z.infer<typeof receipt>;
export type Judgment = z.infer<typeof judgment>;
export type Checkpoint = z.infer<typeof checkpoint>;
export type Status = z.infer<typeof status>;
export type StateOf = z.infer<typeof stateOf>;
export type Preimage = z.infer<typeof preimage>;
export type RecordRef = z.infer<typeof recordRef>;
export type SignerSet = z.infer<typeof signerSet>;
export type Writer = z.infer<typeof writer>;
export type Flow = z.infer<typeof flow>;
export type Verdict = z.infer<typeof verdict>;
export type StageOutcome = z.infer<typeof outcome>;
/** A public key a receiver holds, as a key set carries it. */
export type ReceiverKey = z.infer<typeof publicKey>;
export type ReceiptFault = (typeof tokens.checks.receiptFaults)[number];
export type CallbackFault = (typeof tokens.checks.callbackFaults)[number];

/** R16 (an ID token) and R17 (an access token): what a receiver reads to take a token by its receipt. */
export interface ReceiptCheck {
	/** A token already verified the standard way: its issuer's JWKS signature, `iss`, `aud`, `exp`. */
	readonly token: string;
	readonly frame: (typeof tokens.checks.frames)[number];
	/** The flow the token must be of: a person's token its `sub`'s subject flow, a client's its client flow. */
	readonly flow: Flow;
	/** The newest status the receiver holds, as `setSigned` reads it (JWS JSON General Serialization). */
	readonly status: string;
	/** The log's keys, fixed from C1's source. */
	readonly logKeys: readonly ReceiverKey[];
	/** The status's signer set: its keys by kid and how many of it must sign; the newest version the receiver holds. */
	readonly statusSigners: SignerSet;
	/** The receiver's clock, ms. */
	readonly now: number;
	/** σ: the most the receiver's clock and the log's differ by, ms. */
	readonly skew: number;
	/** R17: a token's life counted from its receipt's time; R16: the oldest a receipt may be. ms. */
	readonly maxAge: number;
}

/** R18 (an `openid` client): the callback's proof, read against the ID token that passed R16. */
export interface CallbackCheck {
	readonly proof: string;
	readonly idToken: {
		readonly esig: string;
		readonly apr: RecordRef;
		readonly iss: string;
		readonly aud: string;
	};
	readonly expected: {
		readonly iss: string;
		readonly client_id: string;
		readonly state: string;
		readonly code: string;
	};
}
