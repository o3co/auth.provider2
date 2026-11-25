import { isUnavailable, type Random } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { localLedger, type Passwords } from "../src/ledger.ts";
import type { IdentifierlessRecord, LocalRecords } from "../src/records/records.ts";

const key = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const random = { bytes: (n: number) => new Uint8Array(n).fill(7) } as unknown as Random;
const passwords = { checker: {}, work: "w" } as unknown as Passwords;

/** Records whose key reads and identifierless placement answer as given, in order: the ledger's steps, each alone. */
function records(
	reads: readonly (IdentifierlessRecord | undefined)[],
	placed: "placed" | "exists" | "taken" | "erased",
): LocalRecords & { readonly placings: string[] } {
	const left = [...reads];
	const placings: string[] = [];
	return {
		placings,
		place: async () => "placed",
		placeIdentifierless: async (k, subject) => {
			placings.push(`${k} ${subject}`);
			return placed;
		},
		byIdentifier: async () => undefined,
		byIdentifierlessKey: async () => left.shift(),
		bySubject: async () => undefined,
	};
}

describe("users-local's identifierless create, step by step", () => {
	it("answers the subject the key holds, placing none", async () => {
		const held = records([{ subject: "s-held" }], "placed");
		expect(await localLedger(held, random, passwords).createIdentifierless?.(key)).toEqual({
			subject: "s-held",
			attributes: {},
		});
		expect(held.placings).toEqual([]);
	});

	it("places a drawn subject under a key it does not hold", async () => {
		const fresh = records([undefined], "placed");
		const made = await localLedger(fresh, random, passwords).createIdentifierless?.(key);
		expect(made?.subject).toBe("07".repeat(16));
		expect(fresh.placings).toEqual([`${key} ${"07".repeat(16)}`]);
	});

	it("answers the subject another placed at once, read back after its placing found the key held", async () => {
		const raced = records([undefined, { subject: "s-theirs" }], "exists");
		expect((await localLedger(raced, random, passwords).createIdentifierless?.(key))?.subject).toBe(
			"s-theirs",
		);
	});

	it("is unavailable where the read back finds none, the drawn subject is held, or it is erased", async () => {
		for (const [reads, placed] of [
			[[undefined, undefined], "exists"],
			[[undefined], "taken"],
			[[undefined], "erased"],
		] as const) {
			await expect(
				localLedger(records(reads, placed), random, passwords).createIdentifierless?.(key),
				placed,
			).rejects.toSatisfy(isUnavailable);
		}
	});
});
