import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { lexicalAnalysis } from "@mod/guard-imports";
import { describe, expect, it } from "vitest";

// The package's internal modules and the others each may read, every edge counted (a type's, a
// re-export's, a dynamic import's): the compromised Core's steps and what both harnesses share never
// reach the dishonest Front. Until guard holds a package's internal modules to a direction.

const reads: Readonly<Record<string, readonly string[]>> = {
	relay: [],
	front: ["relay"],
	roles: ["relay"],
	pattern: ["relay", "roles"],
	world: ["relay", "roles", "pattern"],
	"in-process": ["relay", "roles", "pattern", "world"],
	"front-steps": ["front", "relay", "roles", "pattern", "world"],
	"core-steps": ["relay", "roles", "pattern", "world", "in-process"],
	// The package's `.`: what it offers, re-exported; its own tests read none of its modules.
	"the package's entry": ["front", "relay"],
	"the package's tests": [],
};

const root = fileURLToPath(new URL("../", import.meta.url));
const name = "@mod/attack-harness";

/** The package's files, its dependencies' links left unentered. */
function filesUnder(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) return entry.name === "node_modules" ? [] : filesUnder(path);
		return [path];
	});
}
const all = filesUnder(root);
/** The sources the lexical facts read; any other script would go unread, so none may be here. */
const read = (path: string) => path.endsWith(".ts") || path.endsWith(".mjs");
const scripts = /\.(?:[cm]?[jt]sx?)$/;
const files = all.filter(read);

/** The internal module a package file is in: `src/<module>/…`; the package's own entry and tests are named apart. */
function moduleOf(path: string): string {
	const [top, name, ...rest] = relative(root, path).split(sep);
	if (top === "src" && name === "contract.ts") return "the package's entry";
	if (top === "src" && name !== undefined && rest.length > 0) return name;
	return "the package's tests";
}

/**
 * Each edge from one internal module into another of the package, as `from → to`: the package by its
 * own name is its entry, and a file outside it is named as such (a relative path out and back in
 * would pass a module by).
 */
function crossings(): string[] {
	const analysis = lexicalAnalysis(files);
	return files.flatMap((file) =>
		analysis.factsOf(file).edges.flatMap((edge) => {
			const from = moduleOf(file);
			const { target } = edge;
			if (target.kind === "package") {
				return target.name === name ? [`${from} → the package's entry`] : [];
			}
			if (target.kind !== "file") return [];
			if (!target.path.startsWith(root)) return [`${from} → a file outside the package`];
			const to = moduleOf(target.path);
			return from === to ? [] : [`${from} → ${to}`];
		}),
	);
}

describe("the package's internal modules", () => {
	const found = crossings();

	it("each reads only the modules it may, none of them the package's entry", () => {
		const allowed = (crossing: string) => {
			const [from = "", to = ""] = crossing.split(" → ");
			return reads[from]?.includes(to) ?? false;
		};
		expect([...new Set(found.filter((c) => !allowed(c)))]).toEqual([]);
	});

	it("are those the table names, every file of the package's sources in one, each a source the facts read", () => {
		const unknown = files.map(moduleOf).filter((m) => !(m in reads));
		expect([...new Set(unknown)]).toEqual([]);
		expect(all.filter((path) => scripts.test(path) && !read(path))).toEqual([]);
		// The table's own edges are read: the steps reach the world, the dishonest Front the relay.
		expect(found).toEqual(expect.arrayContaining(["front-steps → world", "front → relay"]));
	});
});
