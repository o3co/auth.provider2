import { type Log, Unavailable } from "@mod/kernel";
import type { Tokens } from "@mod/tokens";
import { fromStored, toStored } from "../codes.ts";
import type { FamilyMaker } from "../contract.ts";
import { markVoid } from "../redemption-record/redemption-record.ts";
import type { CodeStore, RedemptionRecords, VoidList } from "../store/store.ts";

/** A code's voiding: listing, marking, revoking its token, and the sweep that retries it. */
export function voiding(parts: {
	readonly store: Pick<CodeStore, "update">;
	readonly redemptionRecords: RedemptionRecords;
	readonly voids: VoidList;
	readonly tokens: Pick<Tokens, "revokeReferenced">;
	/** The refresh family a redemption founded, ended with its token. */
	readonly families?: Pick<FamilyMaker, "revoke">;
	readonly log: Log;
}) {
	const { store, redemptionRecords, voids, tokens, families, log } = parts;
	/**
	 * Voids a code: listed first, then marked void on its own record and its redemption record, even
	 * if they are already, so the redemption issuing it reads a mark wherever it looks after issuing.
	 * It stays listed until its token is revoked or both its records are gone.
	 */
	const settle = async (name: string) => {
		await voids.add(name);
		const coded = await store.update(name, (stored) => {
			const r = fromStored(stored);
			return r && { value: toStored({ ...r, void: true }) };
		});
		const marked = await markVoid(redemptionRecords, name);
		if (!marked) {
			// Used up by a redemption that has made no record yet: it stays listed while its code is kept.
			if (coded) return;
			log.info("code-grant.void_without_record", {});
			await voids.done(name);
			return;
		}
		// Its family ended first, or marked so that none is founded later, under the code's subject.
		const subject = coded ? fromStored(coded.before)?.subject : undefined;
		if (families && marked.redemption !== undefined)
			await families.revoke(marked.redemption, subject);
		// Not issued yet: the request issuing it sees the mark and voids again.
		if (!marked.token) return;
		const revoked = await tokens.revokeReferenced(marked.token.reference);
		if (revoked.kind === "unsupported") throw new Unavailable("code-grant");
		await voids.done(name);
	};
	const sweep = async () => {
		const { failed } = await voids.each(settle);
		if (failed > 0) log.warn("code-grant.void_retry_failed", { count: failed });
	};
	return { settle, sweep };
}
