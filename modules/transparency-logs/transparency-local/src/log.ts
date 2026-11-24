import { createHash } from "node:crypto";
import {
	type Checks,
	type Context,
	emptyState,
	type FlowEntry,
	type FlowState,
	fold,
	resetFinding,
	ruleSchemas,
} from "@mod/authority-rules";
import { Unavailable } from "@mod/kernel";
import { resetInstruction, resetRefusal } from "@mod/reset-wire";
import { canonicalJson, type Json } from "@mod/store";
import type { Placed, ResetAnswer, TransparencyLog } from "@mod/transparency";
import {
	type AppendAnswer,
	type Flow,
	flows,
	judgments,
	logTyps,
	opIds,
	recordKinds,
	schemas,
	tokens,
} from "@mod/transparency-wire";
import { z } from "zod";
import type { LogStore } from "./contract.ts";
import { type Judging, localKey, type SignedJudging } from "./judging.ts";

/** How many times an append reads again after another moved what it read, before `temporary`. */
const attempts = 8;
/** How long past its read an append may still commit, on the store clock. */
const writeWindowMs = 10_000;
/** The issuer a receipt names, and the image a record's writer names: no log, no attested image. */
const local = "transparency-local";
/** An unsigned receipt's third part: the JWS form holds one, and `alg` `none` says there is no signature. */
const unsigned = Buffer.from("unsigned").toString("base64url");

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
/** Plain JSON: members holding none left out, as the store and the digest read it. */
const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** A compact JWS's payload as the log reads it: one base64url spelling, strict UTF-8, JSON; none otherwise. */
function payloadOf(jws: string): unknown {
	const part = jws.split(".")[1] ?? "";
	const bytes = Buffer.from(part, "base64url");
	if (bytes.toString("base64url") !== part) return undefined;
	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return undefined;
	}
	// The one JSON reading the log's contract holds: a key named twice is none.
	const read = tokens.parse(text);
	return "value" in read ? read.value : undefined;
}

const count = z.number().int().nonnegative();
const finding = z
	.object({ verdict: z.enum(judgments.verdicts), outcome: z.enum(judgments.outcomes) })
	.strict();
const kinds = [...recordKinds.core, ...recordKinds.monitor, ...recordKinds.publisher] as const;
const entry = z
	.object({
		envelope: z
			.object({
				id: z.string(),
				kind: z.enum([...kinds, ...recordKinds.human]),
				op: z.string(),
				stage: count,
				last: z.boolean(),
				position: count,
				acceptedAt: count,
			})
			.strict(),
		changes: ruleSchemas.changes,
		judgment: finding,
		parent: z.string().optional(),
		via: z.enum(["code", "refresh", "client"]).optional(),
		client: z
			.object({
				elements: z.array(z.string()),
				version: count.optional(),
				key: z.string().optional(),
			})
			.strict()
			.optional(),
	})
	.strict();
/** What each key holds: the flow's head, its judged prefix, a position's record, an op's stages. */
const shapes = {
	head: z.object({ head: count }).strict(),
	prefix: z.object({ entries: z.array(entry) }).strict(),
	at: z
		.object({ record: schemas.record, finding, changes: ruleSchemas.changes.optional() })
		.strict(),
	op: z
		.object({
			stages: z.array(
				z.object({ stage: count, position: count, digest: z.string(), last: z.boolean() }).strict(),
			),
			abandonments: count,
		})
		.strict(),
	/** An evidence element a client's start of the flow named: the op of that start. */
	element: z.object({ op: z.string() }).strict(),
};
type Shape<K extends keyof typeof shapes> = z.output<(typeof shapes)[K]>;
/** A stored value read to its shape; another shape is unavailable, never none. */
function readAs<K extends keyof typeof shapes>(shape: K, value: Json | undefined) {
	if (value === undefined) return undefined;
	const read = shapes[shape].safeParse(value);
	if (!read.success) throw new Unavailable("transparency-local");
	return read.data as Shape<K>;
}

/** Each record's key: a flow's words, then what it holds. */
const keysOf = (flow: Flow) => {
	const key = (...words: (string | number)[]) => JSON.stringify([flow.of, flow.id, ...words]);
	return {
		head: key("head"),
		prefix: key("prefix"),
		at: (position: number) => key("at", position),
		op: (op: string) => key("op", op),
		element: (digest: string) => key("element", digest),
	};
};
const placedOf = (at: Shape<"at">): Placed => {
	const { record, finding: judged, changes } = at;
	if (record.kind === "tick") throw new Unavailable("transparency-local");
	return { record, finding: judged, ...(changes ? { changes } : {}) };
};

/** Its receipts, one per token, or one for a record of none: the wire's form, unsigned. */
function receiptsOf(record: Placed["record"]): string[] {
	const { v, id, writer, kind, flow, position, shard, n, acceptedAt, plaintextDigest } = record;
	const body = { v, iss: local, id, writer, kind, flow, position, shard, n, acceptedAt };
	const of = (token?: unknown) =>
		`${b64({ alg: "none", typ: logTyps.receipt })}.${b64(plain({ ...body, plaintextDigest, token, approval: record.approval, keyChange: record.keyChange }))}.${unsigned}`;
	return record.tokens ? record.tokens.map((token) => of(token)) : [of()];
}
const acceptedOf = (r: Placed["record"]): AppendAnswer => ({
	v: 1,
	result: "accepted",
	id: r.id,
	position: r.position,
	shard: r.shard,
	n: r.n,
	acceptedAt: r.acceptedAt,
	receipts: receiptsOf(r),
});
const refused = (
	refusal: "prevMismatch" | "sameIdOther" | "temporary" | "abandoned" | "evidenceUsed",
): AppendAnswer => ({
	v: 1,
	result: "refused",
	refusal,
});

/**
 * t0: the log axis over the Core's own store. A flow's position is the store's count of its records,
 * moved by one write held to what it read; the acceptance time is the kernel's clock; each record
 * is judged (`judging`) as it is placed.
 */
export function localLog(p: {
	readonly store: LogStore;
	readonly writer: { readonly instance: string; readonly generation: number };
	readonly now: () => number;
	readonly id: () => string;
	readonly judging: Judging;
	/** Placing a reset as the monitor does (§B.4): the newest set's version, the checks and context the rule reads, its judgment. */
	readonly resetting?: {
		readonly newest: number | undefined;
		readonly checks: Checks;
		readonly context: Context;
		readonly judging: SignedJudging;
	};
}): TransparencyLog {
	const { store, writer } = p;
	const read1 = async (key: string) => (await store.read([key])).values[0];
	const headOf = async (flow: Flow) => readAs("head", await read1(keysOf(flow).head))?.head ?? 0;
	const digest = (preimage: unknown) => sha256(canonicalJson(plain(preimage) as Json));

	/**
	 * §B.4: the instruction's shape read first, its flow and op from it; the op looked up on the flow,
	 * a placed one answered as placed where the payload is the same and its set's keys verify it,
	 * `conflict` where not; else the rule run on the flow's head with the newest set, any fault
	 * `invalid`, and the boundary placed at the head as the monitor's, judged as placed.
	 */
	async function reset(instruction: string): Promise<ResetAnswer> {
		const r = p.resetting;
		if (!r) throw new TypeError("transparency-local: no reset is set up");
		const payload = payloadOf(instruction);
		const read = resetInstruction.safeParse(payload);
		if (!read.success) return resetRefusal.invalid("shape");
		const flow = { of: "subject", id: read.data.subject } as const;
		const op = opIds.reset(read.data.id);
		const keys = keysOf(flow);
		const canonical = canonicalJson(plain(payload) as Json);
		for (let attempt = 0; attempt < attempts; attempt++) {
			const head = await headOf(flow);
			const held = await store.read([keys.head, keys.prefix, keys.op(op), keys.at(head + 1)]);
			const [heldHead, heldPrefix, heldOp] = held.values;
			const heldOpRead = readAs("op", heldOp);
			// A placed reset is answered before the head is read again: a moving flow never makes it temporary.
			const placed = heldOpRead?.stages[0];
			if (placed) {
				const at = readAs("at", await read1(keys.at(placed.position)));
				const body =
					at && "signed" in at.record && at.record.signed !== undefined
						? payloadOf(at.record.signed)
						: undefined;
				const was = schemas.bodies.resetBoundary.safeParse(body);
				if (!at || !was.success) throw new Unavailable("transparency-local");
				const set = r.context.reset?.sets(was.data.set);
				const same = canonicalJson(plain(payloadOf(was.data.instruction)) as Json) === canonical;
				const verified = Array.isArray(set) ? r.checks.verifyJws(instruction, set) : undefined;
				const typ = (verified?.header as { typ?: unknown } | undefined)?.typ;
				return same && typ === logTyps.resetInstruction
					? acceptedOf(placedOf(at).record)
					: resetRefusal.conflict();
			}
			if ((readAs("head", heldHead)?.head ?? 0) !== head) continue;
			if (r.newest === undefined) return resetRefusal.invalid("set");
			const prior = readAs("prefix", heldPrefix)?.entries ?? [];
			const state = prior.reduce(
				(s, e) => fold(s, e.envelope, e.changes, e.judgment),
				emptyState as FlowState,
			);
			const body = { v: 1, flow, op, prev: head, set: r.newest, instruction };
			const now = p.now();
			const found = resetFinding(body, state, r.checks, r.context, now);
			if (found.verdict === "held") return resetRefusal.invalid("set");
			if (found.reason !== undefined) return resetRefusal.invalid(found.reason);
			const text = JSON.stringify(body);
			const position = head + 1;
			const made = schemas.record.safeParse({
				v: 1,
				kind: "resetBoundary",
				flow,
				op,
				stage: 1,
				last: true,
				plaintextDigest: sha256(text),
				signed: `${b64({ alg: "none", typ: logTyps.resetBoundary })}.${Buffer.from(text).toString("base64url")}.${unsigned}`,
				id: p.id(),
				writer: { role: "monitor", key: localKey },
				position,
				shard: JSON.stringify([flow.of, flow.id]),
				n: position,
				acceptedAt: now,
			});
			if (!made.success || made.data.kind === "tick")
				throw new TypeError(
					`transparency-local: a reset boundary of another form: ${made.error?.message}`,
				);
			const record = made.data;
			const judged: FlowEntry = plain(r.judging(record, body, prior));
			const next: Json[] = [
				{ head: position },
				{ entries: [...prior, judged] } as unknown as Json,
				{
					...(heldOpRead ?? { abandonments: 0 }),
					stages: [{ stage: 1, position, digest: sha256(canonical), last: true }],
				},
				{ record, finding: judged.judgment } as unknown as Json,
			];
			const written = await store.write(held, next, held.now + writeWindowMs);
			if (written === "written") return acceptedOf(record);
		}
		return refused("temporary");
	}
	return {
		writer,
		digest,
		async append(stage, prev) {
			const { flow } = stage;
			const unconditional = (flows.unconditional as readonly string[]).includes(flow.of);
			if (unconditional !== (prev === undefined))
				throw new TypeError(
					"transparency-local: a conditional flow's append names its previous position, an unconditional one's none",
				);
			// A client's start names its client's registry version, judged with no window; no other stage names one.
			const clientStart = stage.kind === "start" && flow.of === "client";
			if (
				(stage.registryVersion !== undefined && !clientStart) ||
				stage.configVersion !== undefined
			)
				throw new TypeError(
					"transparency-local: a stage names a version, which no flow here holds the window of",
				);
			if (clientStart !== (stage.elements !== undefined))
				throw new TypeError(
					"transparency-local: a client's start names its evidence's elements, and no other stage does",
				);
			const keys = keysOf(flow);
			const elements = (stage.elements ?? []).map((e) => keys.element(e));
			const plaintextDigest = digest(stage.preimage);
			const { preimage, ...named } = stage;
			// The stage as named, its preimage by its digest: a resend differing in any field is another.
			const asNamed = digest({ ...named, plaintextDigest });
			for (let attempt = 0; attempt < attempts; attempt++) {
				const head = await headOf(flow);
				const abandoned = stage.abandons ? [keys.op(stage.abandons.op)] : [];
				const read = await store.read([
					keys.head,
					keys.prefix,
					keys.op(stage.op),
					keys.at(head + 1),
					...abandoned,
					...elements,
				]);
				const [heldHead, heldPrefix, heldOp, , ...more] = read.values;
				const heldAbandoned = stage.abandons ? more[0] : undefined;
				const used = more.slice(abandoned.length).map((value) => readAs("element", value));
				if ((readAs("head", heldHead)?.head ?? 0) !== head) continue;
				const op = readAs("op", heldOp) ?? { stages: [], abandonments: 0 };
				const same = op.stages.find((s) => s.stage === stage.stage);
				if (same) {
					if (same.digest !== asNamed) return refused("sameIdOther");
					const at = readAs("at", await read1(keys.at(same.position)));
					if (!at) throw new Unavailable("transparency-local");
					return acceptedOf(placedOf(at).record);
				}
				if (!unconditional && prev !== head) return refused("prevMismatch");
				// Never placed after its op's abandonment, nor naming an element a start used: kept without end.
				if (unconditional && stage.kind !== "abandonment" && op.abandonments > 0)
					return refused("abandoned");
				if (used.some((u) => u !== undefined)) return refused("evidenceUsed");
				const position = head + 1;
				const made = schemas.record.safeParse(
					plain({
						v: 1,
						...named,
						plaintextDigest,
						id: p.id(),
						writer: {
							role: "core",
							instance: writer.instance,
							image: local,
							generation: writer.generation,
						},
						position,
						shard: JSON.stringify([flow.of, flow.id]),
						n: position,
						acceptedAt: p.now(),
						sealedTo: [{ key: localKey, ciphertextHash: plaintextDigest }],
						keySetVersion: 1,
					}),
				);
				if (!made.success || made.data.kind === "tick")
					throw new TypeError(
						`transparency-local: a stage of another form: ${made.error?.message}`,
					);
				const record = made.data;
				const prior = readAs("prefix", heldPrefix)?.entries ?? [];
				const judged: FlowEntry = plain(await p.judging(record, preimage, prior));
				const left = readAs("op", heldAbandoned) ?? { stages: [], abandonments: 0 };
				const next: Json[] = [
					{ head: position },
					{ entries: [...prior, judged] } as unknown as Json,
					{
						...op,
						stages: [
							...op.stages,
							{ stage: stage.stage, position, digest: asNamed, last: stage.last },
						],
					},
					{ record, finding: judged.judgment } as unknown as Json,
					...(stage.abandons ? [{ ...left, abandonments: left.abandonments + 1 }] : []),
					...elements.map(() => ({ op: stage.op })),
				];
				const written = await store.write(read, next, read.now + writeWindowMs);
				if (written === "written") return acceptedOf(record);
			}
			return refused("temporary");
		},
		...(p.resetting ? { reset: (instruction: string) => reset(instruction) } : {}),
		head: headOf,
		async at(flow, position) {
			const at = readAs("at", await read1(keysOf(flow).at(position)));
			return at && placedOf(at);
		},
		async of(flow, op) {
			const held = readAs("op", await read1(keysOf(flow).op(op)));
			return {
				stages: held?.stages.length ?? 0,
				last: held?.stages.some((s) => s.last) ?? false,
				abandonments: held?.abandonments ?? 0,
			};
		},
	};
}
