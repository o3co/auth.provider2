import { canonicalText, continuation } from "@mod/sdk-core-wire";
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
	coseKey,
	creation,
	digest,
	esig,
	type FlowRecord,
	passkeyAdd,
	possession,
	preimage,
	screen,
	sign,
	subject,
} from "./world.ts";

/** A login on a fresh flow, as an honest Core of generation 1 writes it: each step's record and preimage. */

export const newKey = { credential: "cred-1", publicKey: coseKey(1) };
/** The op a key change's record is placed under: the reservation its possession names (P 355). */
export const reservation = "res-1";

/** The first key's creation (signed for key generation `kg`) and possession, by the ring of generation 1. */
const ceremony = (kg = 0) => {
	const creationJws = sign(creation(subject.id, undefined, kg), "ring-1");
	return { creationJws, possessionJws: sign(possession(creationJws, newKey), "ring-1") };
};
export const firstKeyEvidence = ceremony();

/** The first key, its ceremony signed for key generation `kg`, its envelope naming its digests. */
export const firstKey = (position = 1, kg = 0) => {
	const { creationJws, possessionJws } = ceremony(kg);
	const proof = assertion(newKey, possessionJws);
	return {
		record: coreRecord("keyChange", position, {
			op: reservation,
			keyChange: { statement: digest(possessionJws), evidence: digest(proof) },
		}),
		preimage: preimage({
			evidence: [
				{ form: "statement", value: creationJws },
				{ form: "statement", value: possessionJws },
				{ form: "assertion", value: proof },
			],
			content: { variant: "first", ...newKey },
		}),
	};
};

type Key = { readonly credential: string; readonly publicKey: string };
export const addedKey = { credential: "cred-2", publicKey: coseKey(2) };

/** A screen's register continuation over a creation and a body, signed by `key` (the screen's E_sig). */
export const continued = (creationJws: string, body: string, seq = 1, key = screen.e_sig) => {
	const input = continuation.of("register", digest(creationJws), seq, digest(body));
	return canonicalText({ seq, body, signature: esig(key, input) });
};

/** A passkey-add's evidence as an honest Core and screen make it: `approver` approves, `key` is added. */
export function addParts(sid = "add-1", key: Key = addedKey, approver: Key = newKey) {
	const statement = sign(passkeyAdd(sid), "ring-1");
	const basis = { basis: "passkey-add", evidence: digest(statement) };
	const creationJws = sign(creation(subject.id, undefined, 0, undefined, basis), "ring-1");
	const reserved = `res-${sid}`;
	const possessionJws = sign(possession(creationJws, key, undefined, reserved), "ring-1");
	return {
		reservation: reserved,
		statement,
		asserted: assertion(approver, statement),
		creation: creationJws,
		continuation: continued(creationJws, JSON.stringify(key)),
		possession: possessionJws,
		proof: assertion(key, possessionJws),
		key,
	};
}
export type AddParts = ReturnType<typeof addParts>;

/** A key added by the live key `parent`'s approval, its envelope naming its digests. */
export const added = (position: number, parent: string, parts: AddParts = addParts()) => ({
	record: coreRecord("keyChange", position, {
		op: parts.reservation,
		keyChange: { statement: digest(parts.possession), evidence: digest(parts.proof) },
	}),
	preimage: preimage({
		parent,
		evidence: [
			{ form: "statement", value: parts.statement },
			{ form: "assertion", value: parts.asserted },
			{ form: "statement", value: parts.creation },
			{ form: "continuation", value: parts.continuation },
			{ form: "statement", value: parts.possession },
			{ form: "assertion", value: parts.proof },
		],
		content: { variant: "add", ...parts.key },
	}),
});

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
	// The code and the client its approval's record names (`approval`'s, sid-1's code and `rp`).
	preimage: preimage({
		parent: approvalId,
		content: { via: "code", code: digest("code-sid-1"), client: "rp" },
	}),
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

/** A sign-up's (F1) evidence as an honest Core and screen make it: T, its creation, the screen's continuation, the possession. */
export function signUpParts(sid = "signup-1", key: Key = newKey) {
	const t = sign(authorization(sid), "ring-1");
	const basis = { basis: "sign-up", evidence: digest(t) };
	const creationJws = sign(creation(subject.id, undefined, 0, undefined, basis), "ring-1");
	const reserved = `res-${sid}`;
	const possessionJws = sign(possession(creationJws, key, undefined, reserved), "ring-1");
	return {
		reservation: reserved,
		t,
		creation: creationJws,
		continuation: continued(creationJws, JSON.stringify(key)),
		possession: possessionJws,
		proof: assertion(key, possessionJws),
		key,
	};
}
export type SignUpParts = ReturnType<typeof signUpParts>;

/** A first key of `variant: "first"` over the evidence given in its order, its envelope naming its digests. */
export const firstOver = (
	position: number,
	evidence: { form: string; value: string }[],
	key: Key,
	named: { possession: string; proof: string; reservation?: string },
) => ({
	record: coreRecord("keyChange", position, {
		op: named.reservation ?? reservation,
		keyChange: { statement: digest(named.possession), evidence: digest(named.proof) },
	}),
	preimage: preimage({ evidence, content: { variant: "first", ...key } }),
});

/** A sign-up's key (F1) on its flow: [T, creation, continuation, possession, assertion]. */
export const signedUp = (position = 1, parts: SignUpParts = signUpParts()) =>
	firstOver(
		position,
		[
			{ form: "statement", value: parts.t },
			{ form: "statement", value: parts.creation },
			{ form: "continuation", value: parts.continuation },
			{ form: "statement", value: parts.possession },
			{ form: "assertion", value: parts.proof },
		],
		parts.key,
		parts,
	);

/** The first key carrying the screen's continuation: [creation, continuation, possession, assertion]. */
export const firstKeyContinued = (position = 1, body = JSON.stringify(newKey)) => {
	const { creationJws, possessionJws } = firstKeyEvidence;
	const proof = assertion(newKey, possessionJws);
	return firstOver(
		position,
		[
			{ form: "statement", value: creationJws },
			{ form: "continuation", value: continued(creationJws, body) },
			{ form: "statement", value: possessionJws },
			{ form: "assertion", value: proof },
		],
		newKey,
		{ possession: possessionJws, proof },
	);
};

/** The usual login: first key (r-1), approval (r-2), start (r-3) and bundle (r-4) of op `login`. */
export const login = () => [
	firstKey(1),
	approval(2, "r-1"),
	codeStart(3, "login", "r-2"),
	codeBundle(4, "login", "r-3", "r-2"),
];
