import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { Kept, StoredNonce, StoredToken } from "./contract.ts";
import type { section } from "./section.ts";

/** The kinds' items of a start's request, each kind's under its name, as the path hands each its own. */
export { itemsOf } from "./evidence/evidence.ts";

export type PasskeyManagementSettings = z.input<typeof section>;

/** The passkey-management part of a test's configuration, its mail's link at a test URL unless set. */
export const passkeyManagementConfig = (settings: Partial<PasskeyManagementSettings> = {}) => ({
	"passkey-management": { "mail-link": "https://login.example/first-key", ...settings },
});

/** A place that keeps the nonces and the tokens, as one implementation of the store interfaces offers them. */
export interface FirstKeyPlace {
	readonly nonces: Kept<StoredNonce>;
	readonly tokens: Kept<StoredToken>;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
}

const stored = <T>(n: number) => ({ n }) as unknown as T;
const plus = <T>(r: T) => ({ value: stored<T>((r as unknown as { n: number }).n + 1) });

/** The contract of the nonces' and the tokens' store interfaces, run against any implementation. */
export function firstKeyStoreContract(name: string, open: () => Promise<FirstKeyPlace>): void {
	describe(`passkey-management's stores: ${name}`, () => {
		for (const which of ["nonces", "tokens"] as const) {
			it(`keeps a ${which} record's first write for its lifetime, and no longer`, async () => {
				const place = await open();
				const kept = place[which] as Kept<unknown>;
				expect(await kept.create("k", stored(1), 1000)).toBe("created");
				expect(await kept.create("k", stored(2), 1000)).toBe("exists");
				expect(await kept.read("k")).toEqual(stored(1));
				// A store's clock may run on as the test does: the edges are checked with room either side.
				place.advance(900);
				expect(await kept.read("k")).toEqual(stored(1));
				place.advance(200);
				expect(await kept.read("k")).toBeUndefined();
			});

			it(`runs two changes of a ${which} record at once one after the other, and none where it holds none`, async () => {
				const place = await open();
				const kept = place[which] as Kept<unknown>;
				await kept.create("k", stored(1), 60_000);
				await Promise.all([kept.change("k", plus), kept.change("k", plus)]);
				expect(await kept.read("k")).toEqual(stored(3));
				expect(await kept.change("none", plus)).toBeUndefined();
			});

			it(`keeps a ${which} record's lifetime as created, whatever changes it`, async () => {
				const place = await open();
				const kept = place[which] as Kept<unknown>;
				await kept.create("k", stored(1), 1000);
				place.advance(900);
				await kept.change("k", plus);
				place.advance(200);
				expect(await kept.read("k")).toBeUndefined();
			});
		}

		it("keeps the nonces apart from the tokens", async () => {
			const place = await open();
			await place.nonces.create("k", stored(1), 60_000);
			expect(await place.tokens.read("k")).toBeUndefined();
		});
	});
}
