import { createHash } from "node:crypto";
import { type FlowEntry, ruleSchemas } from "@mod/authority-rules";
import { Unavailable } from "@mod/kernel";
import { canonicalJson, type Json } from "@mod/store";
import type { Placed, TransparencyLog } from "@mod/transparency";
import {
	type AppendAnswer,
	type Flow,
	flows,
	judgments,
	logTyps,
	recordKinds,
	schemas,
} from "@mod/transparency-wire";
import { z } from "zod";
import type { LogStore } from "./contract.ts";
import { type Judging, localKey } from "./judging.ts";

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
		via: z.enum(["code", "refresh"]).optional(),
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
		`${b64({ alg: "none", typ: logTyps.receipt })}.${b64(plain({ ...body, plaintextDigest, token, approval: record.approval }))}.${unsigned}`;
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
const refused = (refusal: "prevMismatch" | "sameIdOther" | "temporary"): AppendAnswer => ({
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
}): TransparencyLog {
	const { store, writer } = p;
	const read1 = async (key: string) => (await store.read([key])).values[0];
	const headOf = async (flow: Flow) => readAs("head", await read1(keysOf(flow).head))?.head ?? 0;
	const digest = (preimage: unknown) => sha256(canonicalJson(plain(preimage) as Json));
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
			if (stage.registryVersion !== undefined || stage.configVersion !== undefined)
				throw new TypeError(
					"transparency-local: a stage names a version, which no flow here holds the window of",
				);
			const keys = keysOf(flow);
			const plaintextDigest = digest(stage.preimage);
			for (let attempt = 0; attempt < attempts; attempt++) {
				const head = await headOf(flow);
				const abandoned = stage.abandons ? [keys.op(stage.abandons.op)] : [];
				const read = await store.read([
					keys.head,
					keys.prefix,
					keys.op(stage.op),
					keys.at(head + 1),
					...abandoned,
				]);
				const [heldHead, heldPrefix, heldOp, , heldAbandoned] = read.values;
				if ((readAs("head", heldHead)?.head ?? 0) !== head) continue;
				const op = readAs("op", heldOp) ?? { stages: [], abandonments: 0 };
				const same = op.stages.find((s) => s.stage === stage.stage);
				if (same) {
					if (same.digest !== plaintextDigest) return refused("sameIdOther");
					const at = readAs("at", await read1(keys.at(same.position)));
					if (!at) throw new Unavailable("transparency-local");
					return acceptedOf(placedOf(at).record);
				}
				if (!unconditional && prev !== head) return refused("prevMismatch");
				const position = head + 1;
				const { preimage, ...named } = stage;
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
							{ stage: stage.stage, position, digest: plaintextDigest, last: stage.last },
						],
					},
					{ record, finding: judged.judgment } as unknown as Json,
					...(stage.abandons ? [{ ...left, abandonments: left.abandonments + 1 }] : []),
				];
				const written = await store.write(read, next, read.now + writeWindowMs);
				if (written === "written") return acceptedOf(record);
			}
			return refused("temporary");
		},
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
