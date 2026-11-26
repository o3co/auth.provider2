import { createHash } from "node:crypto";
import type { Changes, Finding } from "@mod/authority-rules";
import { resetInstruction, resetRefusal } from "@mod/reset-wire";
import {
	type AppendAnswer,
	type Flow,
	opIds,
	type Preimage,
	type recordKinds,
} from "@mod/transparency-wire";
import type { Placed, ResetAnswer, Stage, TransparencyLog } from "./contract.ts";

const digest = (text: string) => createHash("sha256").update(text).digest("base64url");
const flowKey = (flow: Flow) => `${flow.of}:${flow.id}`;
const canonical = (value: unknown): string =>
	Array.isArray(value)
		? `[${value.map(canonical).join(",")}]`
		: value !== null && typeof value === "object"
			? `{${Object.keys(value)
					.sort()
					.map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`)
					.join(",")}}`
			: JSON.stringify(value);
const payloadOf = (jws: string): unknown => {
	try {
		return JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString());
	} catch {
		return undefined;
	}
};

/**
 * A log in memory every replica appends to: conditional appends on a subject's flow, unconditional
 * ones on a client's, judgments a test gives (or every append's, once `judgeOnAppend` names one),
 * sends recorded.
 */
export function logBook(now: () => number) {
	const flows = new Map<string, Placed[]>();
	const digests = new Map<string, string>();
	let n = 0;
	let onAppend: Finding | undefined;
	let onReset: Finding = { verdict: "verified", outcome: "took" };
	const resets = new Map<string, string>();
	const sent: { readonly instance: string; readonly stage: Stage; readonly prev?: number }[] = [];
	const onFlow = (flow: Flow) => {
		const placed = flows.get(flowKey(flow)) ?? [];
		flows.set(flowKey(flow), placed);
		return placed;
	};
	const accepted = (p: Placed): AppendAnswer => ({
		v: 1,
		result: "accepted",
		id: p.record.id,
		position: p.record.position,
		shard: p.record.shard,
		n: p.record.n,
		acceptedAt: p.record.acceptedAt,
		// One per token in its order, as the wire's answer carries them; one for a record of none.
		receipts: (p.record.tokens?.length ? p.record.tokens : [undefined]).map((_, i) =>
			i === 0 ? "h.p.s" : `h.p${i}.s`,
		),
	});
	const place = (flow: Flow, fields: Record<string, unknown>, writer: Record<string, unknown>) => {
		const placed = onFlow(flow);
		n += 1;
		const record = {
			v: 1,
			flow,
			stage: 1,
			last: true,
			...fields,
			id: `r${n}`,
			writer,
			position: placed.length + 1,
			shard: "s1",
			n,
			acceptedAt: now(),
		} as unknown as Placed["record"];
		const p: Placed = { record };
		placed.push(p);
		return p;
	};
	const as = (instance: string, generation = 1): TransparencyLog => ({
		writer: { instance, generation },
		digest: (preimage: Preimage) => digest(JSON.stringify(preimage)),
		async append(stage, prev) {
			sent.push({ instance, stage, ...(prev === undefined ? {} : { prev }) });
			const plaintextDigest = digest(JSON.stringify(stage.preimage));
			const placed = onFlow(stage.flow);
			const same = placed.find((p) => p.record.op === stage.op && p.record.stage === stage.stage);
			if (same) {
				return digests.get(same.record.id) === plaintextDigest
					? accepted(same)
					: { v: 1, result: "refused", refusal: "sameIdOther" };
			}
			const unconditional = stage.flow.of === "client";
			if (unconditional !== (prev === undefined))
				throw new TypeError("a client's flow alone names no prev");
			if (!unconditional && prev !== placed.length) {
				return { v: 1, result: "refused", refusal: "prevMismatch" };
			}
			const { preimage: _sealed, ...named } = stage;
			const p = place(
				stage.flow,
				{
					...named,
					plaintextDigest,
					sealedTo: [{ key: "m1", ciphertextHash: digest("c") }],
					keySetVersion: 1,
				},
				{ role: "core", instance, image: "i1", generation },
			);
			digests.set(p.record.id, plaintextDigest);
			if (onAppend) placed[placed.length - 1] = { ...p, finding: onAppend };
			return accepted(p);
		},
		// §B.4 without signatures (none here to check): read the shape, look the op up first, the same
		// payload answered as placed and another refused; else placed at the flow's head.
		async reset(instruction): Promise<ResetAnswer> {
			const payload = payloadOf(instruction);
			const read = resetInstruction.safeParse(payload);
			if (!read.success) return resetRefusal.invalid("shape");
			const flow = { of: "subject", id: read.data.subject } as const;
			const op = opIds.reset(read.data.id);
			const placed = onFlow(flow).find((p) => p.record.op === op);
			if (placed)
				return resets.get(`${flowKey(flow)} ${op}`) === canonical(payload)
					? accepted(placed)
					: resetRefusal.conflict();
			const p = place(
				flow,
				{
					kind: "resetBoundary",
					op,
					plaintextDigest: digest(canonical(payload)),
					signed: instruction,
				},
				{ role: "monitor", key: "mk" },
			);
			resets.set(`${flowKey(flow)} ${op}`, canonical(payload));
			const all = onFlow(flow);
			all[all.length - 1] = { ...p, finding: onReset, changes: {} };
			return accepted(p);
		},
		head: async (flow) => onFlow(flow).length,
		at: async (flow, position) => onFlow(flow)[position - 1],
		of: async (flow, op) => {
			const placed = onFlow(flow).map((p) => p.record);
			return {
				stages: placed.filter((r) => r.op === op).length,
				last: placed.some((r) => r.op === op && r.last),
				abandonments: placed.filter((r) => r.kind === "abandonment" && r.abandons?.op === op)
					.length,
			};
		},
	});
	return {
		as,
		sent,
		/** The finding every later reset is judged with at once (verified and took unless named). */
		judgeResets(finding: Finding) {
			onReset = finding;
		},
		/** The finding every later append is judged with at once, as a local judgment gives it; none stops it. */
		judgeOnAppend(finding: Finding | undefined) {
			onAppend = finding;
		},
		/** The monitor's verdict and outcome on the record at a position. */
		judge(flow: Flow, position: number, finding: Finding) {
			const placed = onFlow(flow);
			const p = placed[position - 1];
			if (!p) throw new Error(`nothing at ${position}`);
			placed[position - 1] = { ...p, finding };
		},
		/** A monitor's record, judged verified at once, its body leaving `changes`. */
		monitor(flow: Flow, kind: (typeof recordKinds.monitor)[number], changes: Changes) {
			const p = place(
				flow,
				{ kind, op: `m${n + 1}`, plaintextDigest: digest("m"), signed: "h.m.s" },
				{
					role: "monitor",
					key: "mk",
				},
			);
			const placed = onFlow(flow);
			placed[placed.length - 1] = {
				...p,
				finding: { verdict: "verified", outcome: "took" },
				changes,
			};
		},
		records: (flow: Flow) => onFlow(flow),
	};
}
