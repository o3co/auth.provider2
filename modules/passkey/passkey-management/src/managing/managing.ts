import type { Approvals, KeptManage, OpenedBody } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import type { KeyList, Passkeys } from "@mod/passkeys";
import type { ContinueAnswer, ContinueStage } from "../contract.ts";

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
		if ((await p.passkeys.publicKeyOf(kept.credential))?.registration !== kept.registration)
			return { refused: "approver" };
		const { credential_id, label } = opened.body;
		if (label === undefined) throw new TypeError("passkey-management: a rename with no label");
		const by = { statement: kept.hash, seq, until: kept.until };
		const renamed = await p.keys.rename({
			subject: kept.subject,
			credential: credential_id,
			label,
			by,
		});
		// The wire's rule is passkeys': a label it read and passkeys refuses is a fault.
		if (renamed === "label")
			throw new TypeError("passkey-management: a label the wire took refused");
		// Renamed, none of the subject's keys, or a later rename's already: the list as it is now.
		const continued = { stage: "rename" as const, seq, bodyHash: opened.bodyHash };
		const listed = await p.approvals.completePasskeyManage({ hash: kept.hash, continued });
		if (listed.kind === "completed") return { enc: listed.enc, ct: listed.ct };
		if (listed.reason === "withdrawn") throw new Unavailable("passkey-management");
		return { refused: listed.reason };
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
			if (done.kind === "refused") return done;
			const result = done.result as Stepped;
			return "refused" in result
				? { kind: "refused", reason: result.refused }
				: { kind: "sealed", enc: result.enc, ct: result.ct };
		},
	};
}
