import { createHash } from "node:crypto";
import type { Changes, Finding } from "@mod/authority-rules";
import type { AppendAnswer, Flow, Preimage, recordKinds } from "@mod/transparency-wire";
import type { Placed, Stage, TransparencyLog } from "../../src/contract.ts";

const digest = (text: string) => createHash("sha256").update(text).digest("base64url");
const flowKey = (flow: Flow) => `${flow.of}:${flow.id}`;

/** A log in memory every replica appends to: conditional appends, judgments a test gives, sends recorded. */
export function logBook(now: () => number) {
	const flows = new Map<string, Placed[]>();
	const digests = new Map<string, string>();
	let n = 0;
	const sent: { readonly instance: string; readonly stage: Stage; readonly prev: number }[] = [];
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
		receipts: ["h.p.s"],
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
			sent.push({ instance, stage, prev });
			const plaintextDigest = digest(JSON.stringify(stage.preimage));
			const placed = onFlow(stage.flow);
			const same = placed.find((p) => p.record.op === stage.op && p.record.stage === stage.stage);
			if (same) {
				return digests.get(same.record.id) === plaintextDigest
					? accepted(same)
					: { v: 1, result: "refused", refusal: "sameIdOther" };
			}
			if (prev !== placed.length) return { v: 1, result: "refused", refusal: "prevMismatch" };
			const { preimage: _sealed, ...named } = stage;
			const p = place(
				stage.flow,
				{ ...named, plaintextDigest, sealedTo: [{ key: "m1", ciphertextHash: digest("c") }] },
				{ role: "core", instance, image: "i1", generation },
			);
			digests.set(p.record.id, plaintextDigest);
			return accepted(p);
		},
		head: async (flow) => onFlow(flow).length,
		at: async (flow, position) => onFlow(flow)[position - 1],
	});
	return {
		as,
		sent,
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
				{ kind, op: `m${n + 1}`, plaintextDigest: digest("m") },
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
