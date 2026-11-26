import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import { parseString } from "@o3co/ts.hocon";
import { expect, it } from "vitest";
import { referenceConfFile, referenceConfOf, sectionsIn } from "../src/contract.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");
const packages = readWorkspace(root);
/** Each package whose manifest gives its section's entry: a module, or the kernel's own. */
const entered = packages.filter((p) => {
	const exports = p.manifest.exports as Readonly<Record<string, string>> | undefined;
	return exports?.["./module"] !== undefined || p.name === "@mod/kernel";
});
const held = packages.filter((p) => existsSync(referenceConfFile(p.dir)));

it("holds the kernel's reference.conf and the modules': a reader that found few would pass on what it missed", () => {
	expect(held.map((p) => p.name)).toContain("@mod/kernel");
	expect(held.length).toBeGreaterThan(40);
});

it.each(entered.map((p) => [p.name, p] as const))(
	"%s: its reference.conf is the one the tool writes from its section's schema, as HOCON",
	async (_, p) => {
		const [section] = await sectionsIn([p]);
		if (!section) return;
		const file = referenceConfFile(p.dir);
		expect(existsSync(file), "run pnpm --filter @mod/references run configuration").toBe(true);
		const text = readFileSync(file, "utf8");
		expect(text, "run pnpm --filter @mod/references run configuration").toBe(
			referenceConfOf(section),
		);
		expect(parseString(text).has(section.section)).toBe(true);
	},
);

it.each(held.map((p) => [p.name, p] as const))(
	"%s: holds a reference.conf only beside a section",
	async (_, p) => {
		expect(await sectionsIn([p])).toHaveLength(1);
	},
);
