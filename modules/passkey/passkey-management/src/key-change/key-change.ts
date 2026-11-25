import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Passkeys, passkeyChanges, type Registrations } from "@mod/passkeys";
import type { Deciding, Json, OperationKind, Stage, Transparency } from "@mod/transparency";
import type { Flow, Preimage } from "@mod/transparency-wire";
import { keyChangePart } from "../contract.ts";

const preimageRecord = { part: keyChangePart, name: "preimage" } as const;

/** A stage kept as this writer kept it, read back: a first key's change, its own op's alone. */
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

/** A first key's change asked: the subject, its verified reservation, the new key, and the ceremony that binds it. */
export interface FirstKeyChange {
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
	| "full";
const commitRefusals = new Set<string>([
	"unknown",
	"state",
	"verification",
	"expired",
	"fenced",
	"held",
	"taken",
	"full",
]);

/**
 * A key change's end: taken in by this writer (`took`) with what the log answered; refused where its
 * reservation would not commit; ended where its op closed otherwise, or was taken in by another
 * replica, or has a stage on the flow already (whether its key is held is the subject's keys' to say).
 */
export type Changed =
	| { readonly kind: "took"; readonly receipts: readonly string[] }
	| { readonly kind: "refused"; readonly reason: CommitRefusal }
	| { readonly kind: "ended" };

/** How often a decision is tried again where the flow moved, ran late or was open, and how often a key change is decided again after a first stage met another. */
const tries = 4;

/**
 * A first key's change, as its writer (KE-C01, C02, C04): decided on the reservation with its preimage
 * kept in the same write, sent, taken in to its end; the subject's keys settled whenever it took in
 * an end, as passkeys asks of whoever does.
 */
export function keyChangesOver(p: {
	readonly registrations: Pick<Registrations, "commit">;
	readonly transparency: Pick<Transparency, "send" | "step" | "tend" | "receiptOf">;
	readonly passkeys: Pick<Passkeys, "settle">;
	readonly digest: (preimage: Preimage) => string;
	readonly pause: (look: number) => Promise<void>;
	readonly looks: number;
}) {
	/** Decided on the applied state: a flow open or not taken in is tended first, then decided again. */
	async function committed(k: FirstKeyChange, flow: Flow, decide: Deciding) {
		for (let tried = 0; tried < tries; tried++) {
			const { subject, reservation, verification } = k;
			const answer = await p.registrations.commit({ subject, reservation, verification, decide });
			if ("prev" in answer) return answer;
			if (commitRefusals.has(answer.refused)) return { refused: answer.refused as CommitRefusal };
			// Its stage is on the flow already: ended here, whoever took its end in.
			if (answer.refused === "ended") return { ended: true as const };
			if (answer.refused === "open" || answer.refused === "notReady") {
				const tended = await p.transparency.tend(flow);
				// An end tended in may be this change's, taken over: settled as its taker settles.
				if (!("refused" in tended) && tended.stepped > 0) await p.passkeys.settle(k.subject);
			} else if (answer.refused !== "moved" && answer.refused !== "late") return unavailable();
		}
		return unavailable();
	}

	/**
	 * Taken in to its end, settled where it took whoever took it in: whether this writer, its owner,
	 * did. A step past `at`, where its stage was placed, finds it taken in by another already.
	 */
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
	async function change(k: FirstKeyChange): Promise<Changed> {
		const { flow, preimage, stage } = stageOf(k);
		// The writer's part: the new key, first trust, and its stage kept beside the reservation.
		const decide: Deciding = (_state, held) => ({
			digest: p.digest(preimage),
			eff: { key: { credential: k.credential, publicKey: k.publicKey } },
			records: held.map((_, i) =>
				i === held.length - 1 ? { value: stage as unknown as Json } : undefined,
			),
		});
		for (let tried = 0; tried < tries; tried++) {
			const decided = await committed(k, flow, decide);
			if ("ended" in decided) return { kind: "ended" };
			if ("refused" in decided) return { kind: "refused", reason: decided.refused };
			const sent = await p.transparency.send({
				flow,
				op: k.reservation,
				stage,
				prev: decided.prev,
			});
			if ("refused" in sent) return unavailable();
			if (sent.answer.result === "accepted") {
				const at = sent.answer.position;
				if (!(await takenIn(k.subject, flow, k.reservation, at))) return { kind: "ended" };
				return { kind: "took", receipts: sent.answer.receipts };
			}
			// A first stage met another before it closed the op with nothing on the flow: decided again.
			const mismatch = sent.answer.result === "refused" && sent.answer.refusal === "prevMismatch";
			if (!sent.end || !mismatch) return sent.end ? { kind: "ended" } : unavailable();
		}
		return unavailable();
	}

	/**
	 * The receipts a change placed already was answered with, asked again of the log with its stage
	 * made again alike; none where the log holds no such stage, or holds another under its op.
	 */
	async function receipts(k: FirstKeyChange): Promise<readonly string[] | undefined> {
		const { flow, stage } = stageOf(k);
		const again = await p.transparency.receiptOf({ flow, op: k.reservation, stage });
		if ("refused" in again) return again.refused === "unplaced" ? undefined : unavailable();
		if (again.answer.result === "accepted") return again.answer.receipts;
		// Another change under its op is none of this one's; any other refusal is the log's, for now.
		return again.answer.refusal === "sameIdOther" ? undefined : unavailable();
	}

	return { change, receipts };
}

/** A first key's change's stage, the same bytes for the same change: its preimage, and what its receipt binds. */
function stageOf(k: FirstKeyChange) {
	const flow: Flow = { of: "subject", id: k.subject };
	const preimage: Preimage = {
		v: 1,
		evidence: [
			{ form: "statement", value: k.creation },
			{ form: "statement", value: k.possession },
			{ form: "assertion", value: k.assertion },
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

const unavailable = (): never => {
	throw new Unavailable("passkey-management");
};
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
