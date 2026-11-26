import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Decided, type Passkeys, passkeyChanges, type Registrations } from "@mod/passkeys";
import { canonicalText } from "@mod/sdk-core-wire";
import type { Deciding, Json, OperationKind, Stage, Transparency } from "@mod/transparency";
import type { Flow, Preimage } from "@mod/transparency-wire";
import { keyChangePart } from "../contract.ts";

const preimageRecord = { part: keyChangePart, name: "preimage" } as const;

/** A stage kept as this writer kept it, read back: a key change, its own op's alone. */
const keptStage = (held: Json | undefined, op: string): Stage | undefined => {
	const r = held as Partial<Stage> | undefined;
	return r?.kind === "keyChange" && r.op === op && r.stage === 1 && r.last === true && r.preimage
		? (r as Stage)
		: undefined;
};

/**
 * The key change's kind as its writer registers it: passkeys' own, with this package's preimage
 * record after passkeys', a resend of the stage it holds, and that record removed at the end.
 */
export const keyChangeKind: OperationKind = {
	...passkeyChanges,
	bundle: false,
	parts: [...passkeyChanges.parts, keyChangePart],
	records: (flow) => [...passkeyChanges.records(flow), preimageRecord],
	end: (end, held) => [...passkeyChanges.end(end, held), { remove: true }],
	resend: (_flow, op, held) => keptStage(held.at(-1), op),
};

/** A passkey-add's approval, as its key change carries it: `registration` is the change's parent. */
export interface Approved {
	readonly statement: string;
	readonly assertion: string;
	readonly credential: string;
	readonly registration: string;
	readonly mark: string;
	readonly generation: number;
}

/** A key added, asked: its reservation, the new key, its ceremony; `approved` by a passkey-add; `signUp`, a sign-up's T. */
export interface AddedKey {
	readonly subject: string;
	readonly reservation: string;
	readonly verification: string;
	readonly credential: string;
	/** The new key's COSE_Key, base64url, as webauthn attested it. */
	readonly publicKey: string;
	/** The creation and possession statements, as signed, and the new key's assertion over the possession. */
	readonly creation: string;
	readonly possession: string;
	readonly assertion: string;
	/** The screen's register continuation over the creation, the one that made the possession. */
	readonly continuation: {
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
	};
	readonly approved?: Approved;
	readonly signUp?: { readonly statement: string };
}

/** Why passkeys would not commit a reservation (its `committing`'s words). */
export type CommitRefusal =
	| "unknown"
	| "state"
	| "verification"
	| "expired"
	| "fenced"
	| "held"
	| "taken"
	| "full"
	| "approver"
	| "used";
const commitRefusals = new Set<string>([
	"unknown",
	"state",
	"verification",
	"expired",
	"fenced",
	"held",
	"taken",
	"full",
	"approver",
	"used",
]);

/** A key added's end: `took` by this writer, `refused` in passkeys' or its own word, else `ended` (the card's). */
export type Changed = Ended<CommitRefusal>;

/** A key change's end, its refusal of words `R`. */
export type Ended<R extends string> =
	| { readonly kind: "took"; readonly receipts: readonly string[] }
	| { readonly kind: "refused"; readonly reason: R }
	| { readonly kind: "ended" };

/** A key deleted, asked: the key named, its op, the passkey-manage that approves it, the screen's continuation. */
export interface DeletedKey {
	readonly subject: string;
	readonly credential: string;
	readonly op: string;
	readonly approval: Omit<Approved, "generation">;
	readonly continuation: {
		readonly seq: number;
		readonly body: string;
		readonly signature: string;
	};
	readonly until: number;
	/** When the call deciding it holds its step no more: past it, another may have answered its number. */
	readonly heldUntil: number;
}

/** A deletion placed already, as the log judged it: none placed; taken, with its receipts; or not taken. */
export type Removed =
	| { readonly kind: "none" }
	| { readonly kind: "took"; readonly receipts: readonly string[] }
	| { readonly kind: "didNotTake" };

/** Why a deletion is not decided: passkeys' (`unknown`, `last`, `op`) and its writer's own. */
export type RemoveRefusal = "unknown" | "last" | "op" | "approver" | "used" | "expired";
const removeRefusals = new Set<string>(["unknown", "last", "op", "approver", "used", "expired"]);

/** How often a decision is tried again where the flow moved, ran late or was open, and how often a key change is decided again after a first stage met another. */
const tries = 4;

/** A key added or deleted's change, as its writer (KE-C01, C02, C04): as the card says. */
export function keyChangesOver(p: {
	readonly registrations: Pick<Registrations, "commit" | "remove">;
	readonly transparency: Pick<Transparency, "send" | "step" | "tend" | "receiptOf" | "applied">;
	readonly passkeys: Pick<Passkeys, "settle">;
	readonly digest: (preimage: Preimage) => string;
	readonly pause: (look: number) => Promise<void>;
	readonly looks: number;
	readonly now: () => number;
}) {
	/** Decided on the applied state: a flow open or not taken in is tended first, then decided again. */
	async function committed<R extends string>(
		subject: string,
		flow: Flow,
		attempt: () => Promise<Decided>,
		words: ReadonlySet<string>,
	): Promise<{ readonly prev: number } | { readonly refused: R } | { readonly ended: true }> {
		for (let tried = 0; tried < tries; tried++) {
			const answer = await attempt();
			if ("prev" in answer) return answer;
			if (words.has(answer.refused)) return { refused: answer.refused as R };
			// Its stage is on the flow already: ended here, whoever took its end in.
			if (answer.refused === "ended") return { ended: true as const };
			if (answer.refused === "open" || answer.refused === "notReady") {
				const tended = await p.transparency.tend(flow);
				// An end tended in may be this change's, taken over: settled as its taker settles.
				if (!("refused" in tended) && tended.stepped > 0) await p.passkeys.settle(subject);
			} else if (answer.refused !== "moved" && answer.refused !== "late") return unavailable();
		}
		return unavailable();
	}

	/** Taken in to its end, settled where it took, whoever took it in: whether this writer, its owner, did. */
	async function takenIn(subject: string, flow: Flow, op: string, at: number): Promise<boolean> {
		for (let look = 0; look < p.looks; look++) {
			const stepped = await p.transparency.step({ flow, own: op });
			if ("position" in stepped) {
				if (stepped.position > at) {
					await p.passkeys.settle(subject);
					return false;
				}
				if (stepped.end?.op !== op) continue;
				if (stepped.end.ending === "took") await p.passkeys.settle(subject);
				return stepped.end.owner === true && stepped.end.ending === "took";
			}
			// A write that moved or ran late kept no end: the end is looked for again.
			if (stepped.refused === "moved" || stepped.refused === "late") continue;
			if (!["unjudged", "atHead", "waits"].includes(stepped.refused)) return unavailable();
			await p.pause(look);
		}
		return unavailable();
	}
	async function change(k: AddedKey): Promise<Changed> {
		const { flow, preimage, stage } = stageOf(k);
		const key = { credential: k.credential, publicKey: k.publicKey };
		const a = k.approved;
		// The writer's part: the new key, by its approver if any, its stage kept beside the reservation.
		const decide: Deciding = (state, held) => {
			if (a) {
				// The approving key live under the registration it approved by; one key from one passkey-add.
				const parent = Object.hasOwn(state.keys, a.registration)
					? state.keys[a.registration]
					: undefined;
				if (parent?.credential !== a.credential) return { refused: "approver" };
				if (state.consumed.includes(a.mark)) return { refused: "used" };
				if (a.generation !== state.keyGeneration) return { refused: "fenced" };
			}
			return {
				digest: p.digest(preimage),
				eff: a ? { key: { ...key, by: a.registration }, consume: [a.mark] } : { key },
				records: held.map((_, i) =>
					i === held.length - 1 ? { value: stage as unknown as Json } : undefined,
				),
			};
		};
		const { subject, reservation, verification } = k;
		const attempt = () => p.registrations.commit({ subject, reservation, verification, decide });
		return placed<CommitRefusal>(subject, flow, reservation, stage, attempt, commitRefusals);
	}

	/** Decided, sent and taken in, decided again where a first stage met another: its end. */
	async function placed<R extends string>(
		subject: string,
		flow: Flow,
		op: string,
		stage: Stage,
		attempt: () => Promise<Decided>,
		words: ReadonlySet<string>,
	): Promise<Ended<R>> {
		for (let tried = 0; tried < tries; tried++) {
			const decided = await committed<R>(subject, flow, attempt, words);
			if ("ended" in decided) return { kind: "ended" };
			if ("refused" in decided) return { kind: "refused", reason: decided.refused };
			const sent = await p.transparency.send({ flow, op, stage, prev: decided.prev });
			if ("refused" in sent) return unavailable();
			if (sent.answer.result === "accepted") {
				const at = sent.answer.position;
				if (!(await takenIn(subject, flow, op, at))) return { kind: "ended" };
				return { kind: "took", receipts: sent.answer.receipts };
			}
			// A first stage met another before it closed the op with nothing on the flow: decided again.
			const mismatch = sent.answer.result === "refused" && sent.answer.refusal === "prevMismatch";
			if (!sent.end || !mismatch) return sent.end ? { kind: "ended" } : unavailable();
		}
		return unavailable();
	}

	/** A key deleted's change: decided on its removal with its stage kept in the same write, then as an add's. */
	async function remove(d: DeletedKey): Promise<Ended<RemoveRefusal>> {
		const { flow, preimage, stage } = deletionStageOf(d);
		const a = d.approval;
		// The writer's part: the approving key live as it approved, one deletion from one passkey-manage, in time.
		const decide: Deciding = (state, held) => {
			const parent = Object.hasOwn(state.keys, a.registration)
				? state.keys[a.registration]
				: undefined;
			if (parent?.credential !== a.credential) return { refused: "approver" };
			if (state.consumed.includes(a.mark)) return { refused: "used" };
			if (p.now() > d.until) return { refused: "expired" };
			// Past its call's hold its number may be another's to answer: a word none keeps, so thrown.
			if (p.now() > d.heldUntil) return { refused: "lapsed" };
			const key = Object.entries(state.keys).find(([, k]) => k.credential === d.credential)?.[0];
			if (key === undefined) return { refused: "unknown" };
			return {
				digest: p.digest(preimage),
				eff: { removeKey: key, consume: [a.mark] },
				records: held.map((_, i) =>
					i === held.length - 1 ? { value: stage as unknown as Json } : undefined,
				),
			};
		};
		const { subject, credential, op } = d;
		const attempt = () => p.registrations.remove({ subject, credential, op, decide });
		return placed<RemoveRefusal>(subject, flow, op, stage, attempt, removeRefusals);
	}

	/** A key added placed already: its receipts, its stage made again alike; none where not placed so. */
	async function receipts(k: AddedKey): Promise<readonly string[] | undefined> {
		const { flow, stage } = stageOf(k);
		return receiptsOf(flow, k.reservation, stage);
	}

	/** A deletion placed already: its outcome as the flow applied it, taken in through its position and settled; thrown while unjudged. */
	async function removed(d: DeletedKey): Promise<Removed> {
		const { flow, stage } = deletionStageOf(d);
		for (let look = 0; look < p.looks; look++) {
			const got = await p.transparency.applied({ kind: keyChangeKind.name, flow, op: d.op, stage });
			if ("refused" in got) {
				if (got.refused === "unplaced") return { kind: "none" };
				if (got.refused !== "unjudged" && got.refused !== "waits") return unavailable();
				if (look < p.looks - 1) await p.pause(look);
				continue;
			}
			if (got.answer.result !== "accepted") return unavailable();
			if (got.ending === undefined)
				throw new TypeError("passkey-management: a deletion's stage is its last");
			if (got.ending !== "took") return { kind: "didNotTake" };
			await p.passkeys.settle(d.subject);
			return { kind: "took", receipts: got.answer.receipts };
		}
		return unavailable();
	}

	async function receiptsOf(flow: Flow, op: string, stage: Stage) {
		const again = await p.transparency.receiptOf({ flow, op, stage });
		if ("refused" in again) return again.refused === "unplaced" ? undefined : unavailable();
		if (again.answer.result === "accepted") return again.answer.receipts;
		// Another change under its op is none of this one's; any other refusal is the log's, for now.
		return again.answer.refusal === "sameIdOther" ? undefined : unavailable();
	}

	return { change, receipts, remove, removed };
}

/** A first key's change's stage, the same bytes for the same change: its preimage, and what its receipt binds. */
function stageOf(k: AddedKey) {
	const flow: Flow = { of: "subject", id: k.subject };
	const a = k.approved;
	const ceremony = [
		{ form: "statement", value: k.creation },
		{ form: "continuation", value: canonicalText(k.continuation) },
		{ form: "statement", value: k.possession },
		{ form: "assertion", value: k.assertion },
	] as const;
	const preimage: Preimage = a
		? {
				v: 1,
				parent: a.registration,
				evidence: [
					{ form: "statement", value: a.statement },
					{ form: "assertion", value: a.assertion },
					...ceremony,
				],
				content: { variant: "add", credential: k.credential, publicKey: k.publicKey },
			}
		: {
				v: 1,
				evidence: [
					...(k.signUp ? [{ form: "statement", value: k.signUp.statement } as const] : []),
					...ceremony,
				],
				content: { variant: "first", credential: k.credential, publicKey: k.publicKey },
			};
	const stage: Stage = {
		kind: "keyChange",
		flow,
		op: k.reservation,
		stage: 1,
		last: true,
		// What its receipt binds: the possession's and the assertion's SHA-256, as an approval's are.
		keyChange: { statement: sha256(k.possession), evidence: sha256(k.assertion) },
		preimage,
	};
	return { flow, preimage, stage };
}

/** A key deleted's stage, the same bytes for the same continuation, as the rules' deletion reads it. */
function deletionStageOf(d: DeletedKey) {
	const flow: Flow = { of: "subject", id: d.subject };
	const a = d.approval;
	const preimage: Preimage = {
		v: 1,
		parent: a.registration,
		evidence: [
			{ form: "statement", value: a.statement },
			{ form: "assertion", value: a.assertion },
			{ form: "continuation", value: canonicalText(d.continuation) },
		],
		content: { variant: "delete", credential: d.credential },
	};
	const stage: Stage = {
		kind: "keyChange",
		flow,
		op: d.op,
		stage: 1,
		last: true,
		keyChange: { statement: sha256(a.statement), evidence: sha256(d.continuation.body) },
		preimage,
	};
	return { flow, preimage, stage };
}

const unavailable = (): never => {
	throw new Unavailable("passkey-management");
};
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
