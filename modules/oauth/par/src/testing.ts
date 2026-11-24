import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { PushedRequests, StoredPush } from "./contract.ts";
import type { section } from "./section.ts";

export type ParSettings = z.input<typeof section>;

/** The par part of a test's configuration. */
export const parConfig = (settings: Partial<ParSettings> = {}) => ({ par: settings });

/** A place that keeps pushed requests, as one implementation of the store interface offers it. */
export interface PushedPlace {
	readonly pushed: PushedRequests;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
}

const stored = (n: number) => ({ n }) as unknown as StoredPush;

/** The contract of the pushed requests' store interface, run against any implementation. */
export function pushedRequestsContract(name: string, open: () => Promise<PushedPlace>): void {
	describe(`par's pushed requests: ${name}`, () => {
		it("keeps a request's first record for its lifetime, and no longer", async () => {
			const place = await open();
			expect(await place.pushed.create("u1", stored(1), 1000)).toBe("created");
			expect(await place.pushed.create("u1", stored(2), 1000)).toBe("exists");
			expect(await place.pushed.read("u1")).toEqual(stored(1));
			expect(await place.pushed.read("u2")).toBeUndefined();
			// A store's clock may run on as the test does: the edges are checked with room either side.
			place.advance(900);
			expect(await place.pushed.read("u1")).toEqual(stored(1));
			place.advance(200);
			expect(await place.pushed.read("u1")).toBeUndefined();
		});
	});
}
