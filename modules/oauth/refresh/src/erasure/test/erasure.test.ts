import type { MigrationReport, SpaceReport } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import { recordsAt } from "../../../test/fixtures.ts";
import { write } from "../../record.ts";
import { familyEraser, familySubjectOf, portsRefused } from "../erasure.ts";

describe("refresh's erasure", () => {
	it("reads every record's own subject, and a record of no kind or another shape as unreadable", async () => {
		expect(await familySubjectOf("k.jkt", write.key("r-1", "alice"))).toEqual({
			kind: "subject",
			subject: "alice",
		});
		expect(
			await familySubjectOf("c.code", write.code({ format: 1, subject: "bob", revoked: true })),
		).toEqual({
			kind: "subject",
			subject: "bob",
		});
		expect(await familySubjectOf("x.other", write.key("r-1", "alice"))).toMatchObject({
			kind: "unreadable",
		});
		expect(await familySubjectOf("f.r-1", { format: 2 })).toMatchObject({ kind: "unreadable" });
	});

	it("erases a subject through the store's own ports, erasable only where it offers both", async () => {
		const records = recordsAt().records;
		const asked: string[] = [];
		const report = { space: "s" } as unknown as SpaceReport;
		const ported = {
			...records,
			erase: async function (this: unknown, subject: string) {
				asked.push(`${subject} ${this === ported}`);
				return report;
			},
			migrate: async () => ({ space: "s" }) as unknown as MigrationReport,
		};
		const eraser = familyEraser(ported);
		expect(eraser).toMatchObject({ name: "refresh", erasable: true });
		expect(await eraser.online("alice", new AbortController().signal)).toEqual({
			reports: [report],
			logoutGaps: 0,
		});
		expect(asked).toEqual(["alice true"]);
		expect(familyEraser(records)).toMatchObject({ erasable: false });
		expect(portsRefused(records)).toBeUndefined();
		expect(portsRefused(ported)).toBeUndefined();
		expect(portsRefused({ ...records, erase: ported.erase })).toMatch(/both, or neither/);
	});
});
