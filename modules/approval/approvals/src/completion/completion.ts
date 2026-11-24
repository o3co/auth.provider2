import { Unavailable } from "@mod/kernel";
import type { Keys } from "@mod/keys";
import { canonicalText, hpke, typs } from "@mod/sdk-core-wire";
import type {
	Deciding,
	Json,
	OperationKind,
	Stage,
	StateOwner,
	Transparency,
} from "@mod/transparency";
import type { Flow, Preimage } from "@mod/transparency-wire";
import type { ApprovalStore, Completed } from "../contract.ts";
import {
	completionIn,
	current,
	itemsIn,
	recordOf,
	type StatementRecord,
	sha256,
	stored,
	wireVersion,
} from "../statement/statement.ts";

/** approvals' part of a subject's flow: the state's fields it holds. */
export const part = "approvals";
const stateRecord = { part, name: "state" } as const;

type FlowState = Parameters<StateOwner["write"]>[0];
type Held = Pick<FlowState, "approvals" | "consumed">;
const heldOf = (held: Json | undefined): Held => {
	const kept = (held ?? {}) as Partial<Held>;
	return { approvals: kept.approvals ?? {}, consumed: kept.consumed ?? [] };
};

/** The owner of the flow state's approvals and use-once marks (a statement's, a code's). */
export const approvalsOwner: StateOwner = {
	name: "approvals",
	holds: ["approvals", "consumed"],
	parts: [part],
	records: () => [stateRecord],
	read: ([held]) => heldOf(held),
	write: (state, [held]) => {
		const next: Held = { approvals: state.approvals, consumed: state.consumed };
		return [
			canonicalText(next) === canonicalText(heldOf(held))
				? undefined
				: { value: next as unknown as Json },
		];
	},
};

/**
 * An approval's kind: one stage, no bundle, no records of its own, and no resend: only its owner holds
 * the code its completion carries, so an orphan is marked and abandoned, never taken over.
 */
export const approvalKind: OperationKind = {
	name: "approval",
	bundle: false,
	parts: [],
	records: () => [],
	end: () => [],
};

/** The use-once mark of a statement, as `authority-rules`' fold names it. */
const statementMark = (sid: string) => `statement:${sid}`;

/** KE-C01 of an approval: its stage made on the state (its key's record), refused once the statement is used. */
export function deciding(
	r: StatementRecord,
	code: string,
	digest: (preimage: Preimage) => string,
	made: (stage: Stage) => void,
): Deciding {
	return (state) => {
		if (state.consumed.includes(statementMark(r.sid))) return { refused: "used" };
		const key = Object.entries(state.keys).find(([, k]) => k.credential === r.credential)?.[0];
		if (key === undefined || r.subject === undefined || r.assertion === undefined)
			return { refused: "key" };
		const flow: Flow = { of: "subject", id: r.subject };
		const stage: Stage = {
			kind: "approval",
			flow,
			op: `approval:${sha256(r.jws)}`,
			stage: 1,
			last: true,
			approval: { statement: sha256(r.jws), assertion: sha256(r.assertion), code: sha256(code) },
			preimage: {
				v: 1,
				parent: key,
				evidence: [
					{ form: "statement", value: r.jws },
					{ form: "assertion", value: r.assertion },
				],
				content: {},
			},
		};
		made(stage);
		const client = (itemsIn(r.jws, "authorization") as { client_id: string }).client_id;
		return {
			digest: digest(stage.preimage),
			eff: { approval: { key, code: sha256(code), client }, consume: [statementMark(r.sid)] },
			records: [],
		};
	};
}

export interface CompletionParts {
	readonly transparency: Transparency;
	readonly digest: (preimage: Preimage) => string;
	readonly keys: Pick<Keys, "prepare" | "sign" | "seal" | "verify">;
	readonly store: ApprovalStore;
	readonly issuer: string;
	readonly now: () => number;
	readonly pause: (look: number) => Promise<void>;
	readonly looks: number;
}

/** Tries to decide while the flow is open: an orphan takes its mark, its abandonment sent, then taken in. */
const decideTries = 4;

/** An authorization's completion: its approval decided, sent, taken in as its owner's `took`, then signed and sealed. */
export function completionsOver(p: CompletionParts) {
	const { transparency } = p;
	const refused = (reason: Extract<Completed, { kind: "refused" }>["reason"]): Completed => ({
		kind: "refused",
		reason,
	});

	async function decided(flow: Flow, op: string, decide: Deciding) {
		for (let tried = 0; tried < decideTries; tried++) {
			const answer = await transparency.decide({ kind: approvalKind.name, flow, op, decide });
			if ("prev" in answer) return answer;
			if (answer.refused === "open" || answer.refused === "notReady") await transparency.tend(flow);
			else if (answer.refused !== "moved") return answer;
		}
		throw new Unavailable("approvals");
	}

	async function takenIn(flow: Flow, op: string) {
		for (let look = 0; look < p.looks; look++) {
			const stepped = await transparency.step({ flow, own: op });
			if ("position" in stepped) {
				if (!stepped.end) continue;
				if (stepped.end.op !== op) continue;
				return stepped.end.owner === true && stepped.end.ending === "took";
			}
			if (stepped.refused === "moved") continue;
			if (!["unjudged", "atHead", "waits"].includes(stepped.refused)) return false;
			await p.pause(look);
		}
		throw new Unavailable("approvals");
	}

	/**
	 * Decides and sends the approval; a first stage refused as `prevMismatch` closed the op with nothing
	 * on the flow, so it is decided again on the flow as it is now.
	 */
	async function placedOn(flow: Flow, op: string, r: StatementRecord, code: string) {
		for (let tried = 0; tried < decideTries; tried++) {
			let stage: Stage | undefined;
			const answer = await decided(
				flow,
				op,
				deciding(r, code, p.digest, (made) => {
					stage = made;
				}),
			);
			if (!("prev" in answer))
				return { refused: answer.refused === "key" ? ("key" as const) : ("ended" as const) };
			const sent = await transparency.send({ flow, op, stage: stage as Stage, prev: answer.prev });
			if ("refused" in sent) throw new Unavailable("approvals");
			if (sent.answer.result === "accepted") {
				const { id, shard, n, acceptedAt } = sent.answer;
				return { record: id, ref: { shard, n }, acceptedAt };
			}
			const mismatch = sent.answer.result === "refused" && sent.answer.refusal === "prevMismatch";
			if (!sent.end || !mismatch) return sent.end ? { refused: "ended" as const } : unavailable();
		}
		return unavailable();
	}
	/** A completion kept on its record, with the approval's record on the flow; none where one is not whole. */
	const keptOf = (r: StatementRecord): Completed => completionIn(r) ?? refused("ended");
	const unavailable = (): never => {
		throw new Unavailable("approvals");
	};

	async function sealed(
		hash: string,
		r: StatementRecord,
		code: string,
		placed: Pick<StatementRecord, "record" | "ref" | "acceptedAt">,
	): Promise<Completed> {
		const nowS = Math.floor(p.now() / 1000);
		const payload = {
			v: wireVersion,
			iss: p.issuer,
			t_hash: hash,
			assertion_hash: sha256(r.assertion as string),
			code,
			iat: nowS,
			exp: Math.floor(r.exp / 1000),
		};
		const prepared = p.keys.prepare("core", typs.completion);
		const signed = await p.keys.sign(prepared, new TextEncoder().encode(canonicalText(payload)));
		if (signed.kind !== "signed") return refused("withdrawn");
		const to = new Uint8Array(Buffer.from(r.e_enc, "base64url"));
		const aad = new TextEncoder().encode(hash);
		const box = await p.keys.seal(
			to,
			hpke.info.completion,
			aad,
			new TextEncoder().encode(signed.jws),
		);
		const enc = Buffer.from(box.enc).toString("base64url");
		const ct = Buffer.from(box.ct).toString("base64url");
		const saved = await p.store.change(hash, (current) => {
			const now = recordOf(current);
			return now?.state === "used"
				? { value: stored({ ...now, state: "completed", enc, ct, code: sha256(code), ...placed }) }
				: undefined;
		});
		// The one kept is answered: another call's, where it kept one first; none where none was kept.
		const after = recordOf(saved?.after);
		return after?.state === "completed" && after.code === sha256(code)
			? keptOf(after)
			: refused("ended");
	}

	return async (q: { readonly hash: string; readonly code: string }): Promise<Completed> => {
		const r = recordOf(await p.store.read(q.hash));
		if (!r) return refused("unknown");
		if (r.purpose !== "authorization") return refused("purpose");
		if (r.state === "completed") return r.code === sha256(q.code) ? keptOf(r) : refused("code");
		if (r.state !== "used" || r.subject === undefined) return refused("unused");
		if (p.now() > r.exp) return refused("expired");
		if (!(await current(p.keys, r.jws))) return refused("unknown");
		const flow: Flow = { of: "subject", id: r.subject };
		const op = `approval:${q.hash}`;
		const placed = await placedOn(flow, op, r, q.code);
		if ("refused" in placed) return refused(placed.refused);
		if (!(await takenIn(flow, op))) return refused("ended");
		return sealed(q.hash, r, q.code, placed);
	};
}
