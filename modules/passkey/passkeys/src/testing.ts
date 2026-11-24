import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { PasskeyStore, StoredCredential } from "./contract.ts";
import type { section } from "./section.ts";

export type PasskeysSettings = z.input<typeof section>;

/** The passkeys part of a test's configuration. */
export const passkeysConfig = (settings: Partial<PasskeysSettings> = {}) => ({
	passkeys: settings,
});

const stored = (n: number) => ({ n }) as unknown as StoredCredential;

/** The contract of the credential records' store interface, run against any implementation. */
export function passkeyStoreContract(name: string, open: () => Promise<PasskeyStore>): void {
	describe(`passkey store contract: ${name}`, () => {
		it("keeps a credential's first record only", async () => {
			const store = await open();
			expect(await store.read("c1")).toBeUndefined();
			expect(await store.create("c1", stored(1))).toBe("created");
			expect(await store.create("c1", stored(2))).toBe("exists");
			expect(await store.read("c1")).toEqual(stored(1));
			expect(await store.read("c2")).toBeUndefined();
		});

		it("changes a record from what it holds, and none where it holds none", async () => {
			const store = await open();
			await store.create("c1", stored(1));
			const next = (r: StoredCredential) => ({
				value: stored((r as unknown as { n: number }).n + 1),
			});
			expect(await store.change("c1", next)).toEqual({ before: stored(1), after: stored(2) });
			expect(await store.change("c1", () => undefined)).toEqual({
				before: stored(2),
				after: stored(2),
			});
			expect(await store.change("c2", next)).toBeUndefined();
			expect(await store.read("c2")).toBeUndefined();
		});
	});
}
