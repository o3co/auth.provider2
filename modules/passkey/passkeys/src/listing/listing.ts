import type { FrameStore } from "@mod/transparency";
import type { KeyList, KeyRow, PasskeyStore } from "../contract.ts";
import { credentialRecord, keysHeld, stored } from "../kept/kept.ts";
import { activeKey, credentialRecordOf, credentialsOf } from "../records/records.ts";

/**
 * A key's label as the keys' list carries it: 1 to 64 code points, none a control, format, surrogate
 * or line or paragraph separator.
 */
const keyLabel = /^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,64}$/u;
export const isKeyLabel = (text: string) => keyLabel.test(text);

/** The keys' list and their renaming, over the applied state and the credential records. */
export function listingOver(p: {
	readonly frames: FrameStore;
	readonly store: PasskeyStore;
	readonly now: () => number;
}): KeyList {
	return {
		async listOf(subject) {
			const rows: KeyRow[] = [];
			for (const credential of credentialsOf(await keysHeld(p.frames, subject))) {
				const details = (await credentialRecord(p.store, credential))?.details;
				rows.push(
					Object.freeze({
						credential,
						// A label kept is given only while it follows the rule now: one rule tightened since shows none.
						...(details?.label !== undefined && isKeyLabel(details.label)
							? { label: details.label }
							: {}),
						...(details?.createdAt !== undefined ? { createdAt: details.createdAt } : {}),
					}),
				);
			}
			return Object.freeze(rows);
		},
		async rename({ subject, credential, label, by }) {
			// A caller's bug, never a person's: a record written with it would read as no record at all.
			const { statement, seq, until } = by;
			if (
				typeof statement !== "string" ||
				statement === "" ||
				!Number.isSafeInteger(seq) ||
				seq < 1 ||
				!Number.isFinite(until)
			)
				throw new TypeError("passkeys: a rename's `by` of another shape");
			// Its three fields alone are kept, whatever else the value carries.
			const kept = { statement, seq, until };
			if (!isKeyLabel(label)) return "label";
			if (!activeKey(await keysHeld(p.frames, subject), credential)) return "unknown";
			let outcome: "renamed" | "unknown" | "stale" = "unknown";
			await p.store.change(credential, (current) => {
				const now = credentialRecordOf(current);
				// One reading of the clock decides the write: its end and what is still running.
				const at = p.now();
				if (now.subject !== subject || !now.details) {
					outcome = "unknown";
					return undefined;
				}
				// Past its statement's end no step of it runs: a write that late is a paused one's.
				if (at > until) {
					outcome = "stale";
					return undefined;
				}
				const running = (now.details.renames ?? []).filter((r) => r.until >= at);
				const last = running.find((r) => r.statement === statement);
				// An earlier number of a statement still running, or its own number with another label, is stale.
				if (last && (seq < last.seq || (seq === last.seq && now.details.label !== label))) {
					outcome = "stale";
					return undefined;
				}
				outcome = "renamed";
				if (last?.seq === seq) return undefined;
				const renames = [...running.filter((r) => r !== last), kept];
				return { value: stored({ ...now, details: { ...now.details, label, renames } }) };
			});
			return outcome;
		},
	};
}
