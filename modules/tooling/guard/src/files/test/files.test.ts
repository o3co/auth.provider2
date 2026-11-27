import type { Pkg } from "@mod/guard-imports";
import { describe, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../check.ts";

// Each case checks a package, its sources bound by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

/** What G35 says of a package, as `where detail`. */
const said = (p: Pkg) =>
	check([p], budget)
		.filter((v) => v.rule.startsWith("G35"))
		.map((v) => `${v.where.replace(`${p.name}/`, "")} ${v.detail}`);

describe("G35 code touching files declares its permissions", () => {
	it("refuses shipped code loading node:fs by any of its names and forms, with no permissions declared", () => {
		const p = pkg("@t/files", {
			"src/a.ts": 'import { readFile } from "node:fs/promises";\nexport const a = readFile;\n',
			"src/b.ts": 'import { readFileSync } from "fs";\nexport const b = readFileSync;\n',
			"src/c.ts": 'export { open } from "fs/promises";\n',
			"src/d.ts": 'export const d = async () => (await import("node:fs")).readFileSync;\n',
			"src/e.ts": 'import "node:fs";\nexport const e = 1;\n',
			"src/h.ts": 'export const h = () => require("fs");\n',
			"src/i.ts": 'import fs = require("node:fs");\nexport const i = fs;\n',
			"src/j.ts":
				'import { createRequire } from "node:module";\nconst load = createRequire(import.meta.url);\nexport const j = load("fs/promises");\n',
			"src/f.ts": 'import type { Stats } from "node:fs";\nexport type F = Stats;\n',
			"test/g.test.ts": 'import { readFileSync } from "node:fs";\nexport const g = readFileSync;\n',
		});
		expect(said(p)).toEqual([
			"src/a.ts node:fs (no permissions declared)",
			"src/b.ts node:fs (no permissions declared)",
			"src/c.ts node:fs (no permissions declared)",
			"src/d.ts node:fs (no permissions declared)",
			"src/e.ts node:fs (no permissions declared)",
			"src/h.ts node:fs (no permissions declared)",
			"src/i.ts node:fs (no permissions declared)",
			"src/j.ts node:fs (no permissions declared)",
		]);
	});

	it("takes a declaration app-permissions takes, an empty one among them, and names the problems of one it does not", () => {
		const files = {
			"src/a.ts": 'import { readFile } from "node:fs/promises";\nexport const a = readFile;\n',
		};
		const manifest = (permissions: unknown) => ({
			exports: { ".": "./src/contract.ts" },
			permissions,
		});
		expect(said(pkg("@t/empty", files, manifest({})))).toEqual([]);
		expect(said(pkg("@t/keys", files, manifest({ read: { keys: ["file"] } })))).toEqual([]);
		expect(said(pkg("@t/bad", files, manifest({ files: ["x"] })))).toEqual([
			"@t/bad permissions.files is no member",
		]);
	});

	it("reads only product packages and companions: a tool's or a verification's files are its own", () => {
		const files = {
			"src/a.ts": 'import { readFile } from "node:fs/promises";\nexport const a = readFile;\n',
		};
		expect(said(pkg("@t/tool", files, undefined, "verification"))).toEqual([]);
		expect(said(pkg("@t/assembly", files, undefined, "assembly"))).toEqual([]);
		expect(said(pkg("@t/companion", files, undefined, "companion"))).toEqual([
			"src/a.ts node:fs (no permissions declared)",
		]);
	});
});
