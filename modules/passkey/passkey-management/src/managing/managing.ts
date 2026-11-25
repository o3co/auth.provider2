import { createHash } from "node:crypto";
import type { Approvals, KeptManage, OpenedBody, PasskeyManageCompleted } from "@mod/approvals";
import { continuations } from "@mod/continuation-wire";
import { Unavailable } from "@mod/kernel";
import type { KeyList, Passkeys } from "@mod/passkeys";
import type { ContinueAnswer, ContinueStage } from "../contract.ts";
import type { DeletedKey, Ended, Removed, RemoveRefusal } from "../key-change/key-change.ts";

/** What a rename's step answers, kept by approvals: the list's completion sealed, or a refusal's word. */
type Stepped = { readonly enc: string; readonly ct: string } | { readonly refused: string };

/**
 * A passkey-manage's `rename` of `/continue`: its sealed continuation taken by approvals, its step
 * renaming the key it names for the subject that approved, then answering the list as it is.
 */
export function renameStageOver(p: {
	readonly approvals: Pick<Approvals, "continueSealed" | "completePasskeyManage">;
	readonly passkeys: Pick<Passkeys, "publicKeyOf">;
	readonly keys: Pick<KeyList, "rename">;
}): ContinueStage {
	const step = async (kept: KeptManage, opened: OpenedBody, seq: number): Promise<Stepped> => {
		// The approving key as it was when it approved: one removed since, or registered again, renames none.
		if (
			(await p.passkeys.publicKeyOf(kept.used.credential))?.registration !== kept.used.registration
		)
			return { refused: "approver" };
		const { credential_id, label } = opened.body;
		if (label === undefined) throw new TypeError("passkey-management: a rename with no label");
		const by = { statement: kept.hash, seq, until: kept.until };
		const renamed = await p.keys.rename({
			subject: kept.used.subject,
			credential: credential_id,
			label,
			by,
		});
		// The wire's rule is passkeys': a label it read and passkeys refuses is a fault.
		if (renamed === "label")
			throw new TypeError("passkey-management: a label the wire took refused");
		// Renamed, none of the subject's keys, or a later rename's already: the list as it is now.
		const continued = { stage: "rename" as const, seq, bodyHash: opened.bodyHash };
		return answered(await p.approvals.completePasskeyManage({ hash: kept.hash, continued }));
	};
	return {
		stage: "rename",
		continue: async (q): Promise<ContinueAnswer> => {
			// A rename's continuation comes sealed: `continuation-wire` seals every rename.
			if (!("sealed" in q)) throw new TypeError("passkey-management: a rename in the clear");
			const done = await p.approvals.continueSealed({
				hash: q.hash,
				stage: "rename",
				seq: q.seq,
				sealed: q.sealed,
				step: (kept, opened) => step(kept, opened, q.seq),
			});
			return stageAnswer(done);
		},
	};
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
/** A statement's expiry as signed, in ms. */
const expiryOf = (statement: string) =>
	Number(JSON.parse(Buffer.from(statement.split(".")[1] ?? "", "base64url").toString("utf8")).exp) *
	1000;

/** A sealed stage's answer, its step's: the completion sealed, a refusal's word kept, or thrown to run again. */
const answered = (done: PasskeyManageCompleted): Stepped => {
	if (done.kind === "completed") return { enc: done.enc, ct: done.ct };
	// The ring signing no more, or the step's hold lapsed: passing, never kept.
	if (done.reason === "withdrawn" || done.reason === "continued")
		throw new Unavailable("passkey-management");
	return { refused: done.reason };
};

/** Taken as a sealed stage's continuation: its answer kept, or a refusal's word. */
const stageAnswer = (done: Awaited<ReturnType<Approvals["continueSealed"]>>): ContinueAnswer => {
	if (done.kind === "refused") return done;
	const result = done.result as Stepped;
	return "refused" in result
		? { kind: "refused", reason: result.refused }
		: { kind: "sealed", enc: result.enc, ct: result.ct };
};

/**
 * A passkey-manage's `delete` of `/continue`: a deletion placed already is completed from the log
 * first, whatever changed since; else, by the approving key as it approved, the key named is
 * deleted, or the list answered with why not. One answer per number, the first kept.
 */
export function deleteStageOver(p: {
	readonly approvals: Pick<Approvals, "continueSealed" | "completePasskeyManage">;
	readonly keyChange: {
		remove(d: DeletedKey): Promise<Ended<RemoveRefusal>>;
		removed(d: DeletedKey): Promise<Removed>;
	};
}): ContinueStage {
	const step = async (kept: KeptManage, opened: OpenedBody, seq: number): Promise<Stepped> => {
		const { used } = kept;
		const credential = opened.body.credential_id;
		const body = continuations.bodyText("delete", opened.body);
		if (body === undefined) throw new TypeError("passkey-management: a delete of another shape");
		const d: DeletedKey = {
			subject: used.subject,
			credential,
			op: sha256(JSON.stringify({ h: kept.hash, stage: "delete", seq })),
			approval: {
				statement: used.statement,
				assertion: used.assertion,
				credential: used.credential,
				registration: used.registration,
				mark: used.mark,
			},
			continuation: { seq, body, signature: opened.signature },
			until: expiryOf(used.statement),
			heldUntil: opened.heldUntil,
		};
		const named = { stage: "delete" as const, seq, bodyHash: opened.bodyHash };
		const complete = async (continued: Parameters<typeof p.approvals.completePasskeyManage>[0]) =>
			answered(await p.approvals.completePasskeyManage(continued));
		/** As the log judged its record: taken, its key change; not taken, a word of its own; unplaced, none. */
		const judged = async (): Promise<Stepped | undefined> => {
			const outcome = await p.keyChange.removed(d);
			if (outcome.kind === "none") return undefined;
			if (outcome.kind === "didNotTake") return { refused: "ended" };
			const [receipt] = outcome.receipts;
			if (receipt === undefined) throw new Unavailable("passkey-management");
			return complete({ hash: kept.hash, continued: { ...named, credential, receipt } });
		};
		// A deletion of this continuation placed already, by this call's first run or another replica.
		const before = await judged();
		if (before) return before;
		// The approving key as it approved, read by the writer in its decision, on the same state.
		const removed = await p.keyChange.remove(d);
		if (removed.kind !== "refused") {
			const after = await judged();
			if (after) return after;
			throw new Unavailable("passkey-management");
		}
		const why = removed.reason;
		if (why === "last" || why === "used" || why === "unknown")
			return complete({ hash: kept.hash, continued: { ...named, refused: why } });
		if (why === "op") throw new TypeError("passkey-management: a delete's op is a reservation's");
		return { refused: why };
	};
	return {
		stage: "delete",
		continue: async (q): Promise<ContinueAnswer> => {
			// A delete's continuation comes sealed: `continuation-wire` seals every delete.
			if (!("sealed" in q)) throw new TypeError("passkey-management: a delete in the clear");
			const done = await p.approvals.continueSealed({
				hash: q.hash,
				stage: "delete",
				seq: q.seq,
				sealed: q.sealed,
				step: (kept, opened) => step(kept, opened, q.seq),
			});
			return stageAnswer(done);
		},
	};
}
