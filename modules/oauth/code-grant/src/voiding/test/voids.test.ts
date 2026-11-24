import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import {
	fromStoredRedemptionRecord,
	toStoredRedemptionRecord,
} from "../../redemption-record/redemption-record.ts";
import type { RedemptionRecords, StoredRedemptionRecord } from "../../store/store.ts";
import { voiding } from "../voiding.ts";

it("settles a listed void alike whichever instance's sweep reaches it, both at once among them", async () => {
	const stand = memoryRecords<StoredRedemptionRecord>(() => 0, { shards: 1, perShard: 10 });
	const redemptionRecords: RedemptionRecords = {
		create: stand.records.create,
		read: stand.records.read,
		update: stand.records.change,
	};
	// A redemption whose token was noted, and whose code came again.
	const noted = { format: 1, token: { reference: "ref-1", expiresAt: 60_000 } } as const;
	await stand.records.create("n1", toStoredRedemptionRecord(noted), 60_000);
	await stand.deferred.add("n1");
	const logged = recordingLog();
	const revoked: string[] = [];
	/** One instance's sweep, over the records and void list every instance shares. */
	const instance = () =>
		voiding({
			store: { update: async () => undefined },
			redemptionRecords,
			voids: stand.deferred,
			tokens: {
				revokeReferenced: async (reference: string) => {
					revoked.push(reference);
					return { kind: "revoked" };
				},
			},
			log: logged.log,
		});
	const [one, other] = [instance(), instance()];
	await Promise.all([one.sweep(), other.sweep()]);
	await other.sweep();
	// Void, its token revoked at most once by each instance, and no longer listed.
	expect(fromStoredRedemptionRecord(await stand.records.read("n1"))?.void).toBe(true);
	expect([new Set(revoked), revoked.length <= 2]).toEqual([new Set(["ref-1"]), true]);
	expect(stand.pending()).toEqual([]);
	expect(logged.lines()).toEqual([]);
});
