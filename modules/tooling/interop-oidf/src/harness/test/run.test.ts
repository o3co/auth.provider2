import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ledger } from "../../deviations/deviations.ts";
import { expectedFor } from "../../expected/expected.ts";
import { timingA } from "./modules.ts";
import { outProblem, parJarMaxLifetimeA, runA, runAms } from "./run.ts";

const repository = fileURLToPath(new URL("../../../../../../", import.meta.url));

describe("run A", () => {
	it("takes PAR's JAR lifetime as par's default, since the run sets none", () => {
		const reference = readFileSync(join(repository, "modules/oauth/par/reference.conf"), "utf8");
		expect(reference).toMatch(new RegExp(`jar-max-lifetime = ${parJarMaxLifetimeA}s\\b`));
	});

	it("writes its record outside every git work tree, links followed, and never over a record, refusing before anything starts", async () => {
		for (const inside of [join(repository, ".oidf-run"), join(repository, "..records"), repository])
			expect(outProblem(inside)).toMatch(/is in the git work tree at /);
		const outside = mkdtempSync(join(tmpdir(), "oidf-run-a-test-"));
		try {
			expect(outProblem(join(outside, "fresh"))).toBeUndefined();
			symlinkSync(repository, join(outside, "linked"));
			expect(outProblem(join(outside, "linked", "record"))).toMatch(/is in the git work tree at /);
			mkdirSync(join(outside, "pointing"));
			symlinkSync(join(repository, "modules"), join(outside, "pointing", "a"));
			expect(outProblem(join(outside, "pointing"))).toMatch(/is in the git work tree at /);
			mkdirSync(join(outside, "dangling"));
			symlinkSync(join(repository, "not-yet-made"), join(outside, "dangling", "a"));
			expect(outProblem(join(outside, "dangling"))).toMatch(/is in the git work tree at /);
			mkdirSync(join(outside, "used", "a"), { recursive: true });
			writeFileSync(join(outside, "used", "a", "report.md"), "an earlier run's");
			expect(outProblem(join(outside, "used"))).toBe(
				`${join(outside, "used", "a")} holds a record already`,
			);
			await expect(runA(join(outside, "used"))).rejects.toThrow("holds a record already");
		} finally {
			rmSync(outside, { recursive: true, force: true });
		}
		await expect(runA(join(repository, ".oidf-run"))).rejects.toThrow("is in the git work tree");
	});

	it("starts no module more past a deadline later than every module of the plan taking its time", () => {
		const modules = expectedFor(
			"a",
			ledger().map((d) => d.key),
		).length;
		expect(runAms).toBeGreaterThan(modules * timingA.moduleMs);
	});
});
