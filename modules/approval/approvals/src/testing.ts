import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { ApprovalStore, StoredStatement } from "./contract.ts";
import type { section } from "./section.ts";

export type ApprovalsSettings = z.input<typeof section>;

/** The approvals part of a test's configuration. */
export const approvalsConfig = (settings: Partial<ApprovalsSettings> = {}) => ({
	approvals: settings,
});

/** A place that keeps statements' records, as one implementation of the store interface offers it. */
export interface ApprovalPlace {
	readonly store: ApprovalStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost, the place replicates, restarts and runs short of memory: each so. */
	readonly loseNextAnswer?: () => void;
	readonly failover?: () => Promise<void>;
	readonly restart?: () => Promise<void>;
	readonly pressMemory?: () => Promise<void>;
}

const stored = (n: number) => ({ n }) as unknown as StoredStatement;
const plus = (r: StoredStatement) => ({ value: stored((r as unknown as { n: number }).n + 1) });

/** The contract of the statements' store interface, run against any implementation. */
export function approvalStoreContract(name: string, open: () => Promise<ApprovalPlace>): void {
	describe(`approvals' store interface: ${name}`, () => {
		it("keeps a statement's first record for its lifetime, and no longer", async () => {
			const place = await open();
			expect(await place.store.create("h1", stored(1), 1000)).toBe("created");
			expect(await place.store.create("h1", stored(2), 1000)).toBe("exists");
			expect(await place.store.read("h1")).toEqual(stored(1));
			// A store's clock may run on as the test does: the edges are checked with room either side.
			place.advance(900);
			expect(await place.store.read("h1")).toEqual(stored(1));
			place.advance(200);
			expect(await place.store.read("h1")).toBeUndefined();
		});

		it("changes a record from what it holds, and none where it holds none", async () => {
			const place = await open();
			await place.store.create("h1", stored(1), 60_000);
			expect(await place.store.change("h1", plus)).toEqual({
				before: stored(1),
				after: stored(2),
			});
			expect(await place.store.change("h1", () => undefined)).toEqual({
				before: stored(2),
				after: stored(2),
			});
			expect(await place.store.change("h2", plus)).toBeUndefined();
		});

		it("runs two changes at once one after the other, each from what the other left, keeping the lifetime", async () => {
			const place = await open();
			await place.store.create("h1", stored(1), 1000);
			await Promise.all([place.store.change("h1", plus), place.store.change("h1", plus)]);
			expect(await place.store.read("h1")).toEqual(stored(3));
			place.advance(1100);
			expect(await place.store.read("h1")).toBeUndefined();
		});

		it("keeps records and their changes through faults", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			await place.store.create("h1", stored(1), 60_000);
			lose();
			await place.store.change("h1", plus);
			await failover();
			await restart();
			await pressMemory();
			expect(await place.store.read("h1")).toEqual(stored(2));
		});
	});
}
