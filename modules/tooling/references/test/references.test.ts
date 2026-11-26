import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import { parseString } from "@o3co/ts.hocon";
import { expect, it } from "vitest";
import { referenceConfFile, referenceConfOf, sectionsIn } from "../src/contract.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");

it("finds every reference.conf as the tool writes it from its section's schema, HOCON, and none without a section", async () => {
	const packages = readWorkspace(root);
	const sections = await sectionsIn(packages);
	// The kernel's and the modules' each: a reader that found few would pass on what it missed.
	expect(sections.map((s) => s.section)).toContain("kernel");
	expect(sections.length).toBeGreaterThan(40);
	// Each file differing from what the tool writes, by its owner: none, or run the tool.
	const differing = sections.filter((section) => {
		const file = referenceConfFile(section.dir);
		return !existsSync(file) || readFileSync(file, "utf8") !== referenceConfOf(section);
	});
	expect(
		differing.map((s) => s.owner),
		"run pnpm --filter @mod/references run configuration",
	).toEqual([]);
	for (const section of sections) {
		const tree = parseString(readFileSync(referenceConfFile(section.dir), "utf8"));
		expect(tree.has(section.section), section.owner).toBe(true);
	}
	const held = new Set(sections.map((s) => s.dir));
	const stray = packages.filter((p) => existsSync(referenceConfFile(p.dir)) && !held.has(p.dir));
	expect(stray.map((p) => p.name)).toEqual([]);
});
