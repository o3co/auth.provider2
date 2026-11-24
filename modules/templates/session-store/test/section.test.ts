import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";

describe("session-store section", () => {
	it("spreads the list over 1,024 shards of 1,000, unless told otherwise", () => {
		expect(section.parse({})).toEqual({ "closing-shards": 1024, "closings-per-shard": 1000 });
	});

	it("refuses sizes out of range", () => {
		for (const bad of [
			{ "closing-shards": 0 },
			{ "closing-shards": 65_537 },
			{ "closings-per-shard": 0 },
			{ "closings-per-shard": 10_001 },
			{ "closing-shards": 1.5 },
		]) {
			expect(section.safeParse(bad).success).toBe(false);
		}
		expect(section.parse({ "closing-shards": 65_536, "closings-per-shard": 10_000 })).toBeDefined();
	});

	it("holds no cap of a subject's listing: session-lifecycle's section sets it", () => {
		const read = section.safeParse({ "sessions-per-subject": 100 });
		expect(read.error?.issues).toEqual([
			expect.objectContaining({ code: "unrecognized_keys", keys: ["sessions-per-subject"] }),
		]);
	});
});
