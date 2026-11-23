import type { Ask } from "../../src/chain/chain.ts";
import { effectOf } from "../../src/chain/chain.ts";
import {
	emptyState,
	type Finding,
	type FlowEntry,
	type FlowState,
	fold,
} from "../../src/fold/fold.ts";
import {
	assertion,
	authorization,
	checks,
	context,
	coreRecord,
	creation,
	digest,
	type FlowRecord,
	point,
	possession,
	preimage,
	sign,
	subject,
} from "./world.ts";

/** A login on a fresh flow, as an honest Core of generation 1 writes it: each step's record and preimage. */

export const newKey = { credential: "cred-1", publicKey: point(1) };
/** The first key's creation (signed for key generation `kg`) and possession, by the ring of generation 1. */
const ceremony = (kg = 0) => {
	const creationJws = sign(creation(subject.id, undefined, kg), "ring-1");
	return { creationJws, possessionJws: sign(possession(creationJws, newKey), "ring-1") };
};
export const firstKeyEvidence = ceremony();

/** The first key, its ceremony signed for key generation `kg`. */
export const firstKey = (position = 1, kg = 0) => {
	const { creationJws, possessionJws } = ceremony(kg);
	return {
		record: coreRecord("keyChange", position),
		preimage: preimage({
			evidence: [
				{ form: "statement", value: creationJws },
				{ form: "statement", value: possessionJws },
				{ form: "assertion", value: assertion(newKey, possessionJws) },
			],
			content: { variant: "first", ...newKey },
		}),
	};
};

export const approval = (position: number, key: string, sid = "sid-1") => {
	const t = sign(authorization(sid), "ring-1");
	const a = assertion(newKey, t);
	return {
		record: coreRecord("approval", position, {
			approval: { statement: digest(t), assertion: digest(a), code: digest(`code-${sid}`) },
		}),
		preimage: preimage({
			parent: key,
			evidence: [
				{ form: "statement", value: t },
				{ form: "assertion", value: a },
			],
		}),
	};
};

const tokens = [
	{ frame: "accessToken", digest: "a".repeat(43) },
	{ frame: "family", digest: "f".repeat(43) },
] as const;

export const codeStart = (position: number, op: string, approvalId: string) => ({
	record: coreRecord("start", position, { op, last: false }),
	preimage: preimage({ parent: approvalId, content: { via: "code" } }),
});
export const codeBundle = (position: number, op: string, start: string, approvalId: string) => ({
	record: coreRecord("bundle", position, { op, stage: 2, tokens: [...tokens] }),
	preimage: preimage({ parent: start, root: approvalId, content: { via: "code" } }),
});
export const refreshStart = (position: number, op: string, family: string, rotation = 0) => ({
	record: coreRecord("start", position, { op, last: false }),
	preimage: preimage({ parent: family, content: { via: "refresh", rotation } }),
});
export const refreshBundle = (
	position: number,
	op: string,
	start: string,
	family: string,
	rotation = 0,
) => ({
	record: coreRecord("bundle", position, { op, stage: 2, tokens: [...tokens] }),
	preimage: preimage({ parent: start, root: family, content: { via: "refresh", rotation } }),
});

export type Step = { record: FlowRecord; preimage: unknown };

export const askOf = (step: Step, state: FlowState, prior: readonly FlowEntry[]): Ask => ({
	record: step.record,
	preimage: step.preimage,
	state,
	prior,
	checks,
	context: context(),
});

/** The envelope the fold reads, from a placed record. */
export const envelopeOf = (r: FlowRecord) => ({
	id: r.id,
	kind: r.kind,
	op: r.op,
	stage: r.stage,
	last: r.last,
	position: r.position,
	acceptedAt: r.acceptedAt,
});

const took: Finding = { verdict: "verified", outcome: "took" };

/** Folds the steps with the judgments given (verified and took by default), as a judged prefix. */
export function prefixOf(steps: readonly (Step & { judgment?: Finding })[]) {
	let state = emptyState;
	const prior: FlowEntry[] = [];
	for (const step of steps) {
		const changes = effectOf(askOf(step, state, prior));
		const judgment = step.judgment ?? took;
		const read = step.preimage as { parent?: string; content?: { via?: "code" | "refresh" } };
		const via = read.content?.via;
		const entry = { envelope: envelopeOf(step.record), changes, judgment, parent: read.parent };
		prior.push(via === undefined ? entry : { ...entry, via });
		state = fold(state, envelopeOf(step.record), changes, judgment);
	}
	return { state, prior };
}

/** The usual login: first key (r-1), approval (r-2), start (r-3) and bundle (r-4) of op `login`. */
export const login = () => [
	firstKey(1),
	approval(2, "r-1"),
	codeStart(3, "login", "r-2"),
	codeBundle(4, "login", "r-3", "r-2"),
];
