import { describe, expect, it } from "vitest";
import { z } from "zod";
import { section } from "../src/section.ts";

const caps = { "groups-limit": 64, "group-limit": 256, "picture-limit": 2048 };

describe("session-lifecycle's section", () => {
	it("reads the sweep's interval written with its unit, as seconds, and the sessions a subject's listing holds", () => {
		expect(section.parse({ "sweep-interval": "1m", "sessions-per-subject": 50 })).toEqual({
			"sweep-interval": 60,
			"sessions-per-subject": 50,
			attributes: caps,
		});
	});

	it("refuses the sweep's interval as a bare number, or a string of digits only", () => {
		expect(section.safeParse({ "sweep-interval": 60 }).success).toBe(false);
		expect(section.safeParse({ "sweep-interval": "60" }).success).toBe(false);
	});

	it("takes the sweep's interval from 1s to 1h, and nothing outside", () => {
		const parses = (seconds: number) =>
			section.safeParse({ "sweep-interval": `${seconds}s` }).success;
		expect([parses(0), parses(1), parses(3600), parses(3601)]).toEqual([false, true, true, false]);
	});

	it("takes a subject's listing from 1 to 10,000 sessions, whole, and nothing outside", () => {
		const parses = (count: number) => section.safeParse({ "sessions-per-subject": count }).success;
		expect([parses(0), parses(1), parses(10_000), parses(10_001), parses(1.5)]).toEqual([
			false,
			true,
			true,
			false,
			false,
		]);
	});

	it("holds no lifetime and no recent-authentication window: a session ends at the end its opening was given", () => {
		for (const key of ["lifetime", "recent-authentication"]) {
			const read = section.safeParse({ [key]: "1h" });
			expect(read.error?.issues).toEqual([
				expect.objectContaining({ code: "unrecognized_keys", keys: [key] }),
			]);
		}
	});

	it("sweeps every 30 seconds and lists 1,000 sessions a subject, where nothing is set", () => {
		expect(section.parse({})).toEqual({
			"sweep-interval": 30,
			"sessions-per-subject": 1000,
			attributes: caps,
		});
	});

	it("writes each default as an operator writes it", () => {
		const { properties } = z.toJSONSchema(section, { io: "input" }) as {
			properties: Record<string, { default: unknown }>;
		};
		expect([
			properties["sweep-interval"]?.default,
			properties["sessions-per-subject"]?.default,
		]).toEqual(["30s", 1000]);
	});
});
