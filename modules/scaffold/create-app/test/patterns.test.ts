import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { composed, reached } from "@mod/combinations";
import { readWorkspace } from "@mod/guard-imports";
import { promiseNames } from "@mod/promises";
import { sectionsIn } from "@mod/references";
import { parse } from "@o3co/ts.hocon";
import { describe, expect, it, vi } from "vitest";
import { noticesOf, patternNamed, patterns, run, selectionOf } from "../src/contract.ts";

// Reading the workspace's sections imports every module: slow on a loaded machine.
vi.setConfig({ testTimeout: 60_000 });

const named = (name: string) => {
	const pattern = patternNamed(name);
	if (!pattern) throw new Error(name);
	return pattern;
};
const composedBy = (name: string, plan = {}) => composed(selectionOf(named(name), plan));

describe("the patterns", () => {
	it("are the three canonical names, each composing the adapter it names for each axis it names", () => {
		expect(patterns.map((p) => p.name)).toEqual(["nextgen-front", "nextgen-core", "nextgen-dev"]);
		for (const pattern of patterns) {
			const modules = composedBy(pattern.name);
			for (const [owner, adapter] of Object.entries(pattern.axes)) {
				expect(modules, `${pattern.name}: ${owner}`).toContain(adapter);
			}
		}
		expect(Object.keys(named("nextgen-core").axes)).toHaveLength(9);
		expect(Object.keys(named("nextgen-dev").axes)).toHaveLength(9);
	});

	it("give the Front no key, log, store or authentication, and one metrics publisher to each", () => {
		const front = composedBy("nextgen-front");
		for (const absent of [
			"@mod/keys",
			"@mod/transparency",
			"@mod/store",
			"@mod/authorize",
			"@mod/passkeys",
		]) {
			expect(front).not.toContain(absent);
		}
		const publishers = (m: readonly string[]) => m.filter((n) => n.startsWith("@mod/metrics-"));
		expect(publishers(front)).toEqual(["@mod/metrics-prometheus"]);
		expect(publishers(composedBy("nextgen-core"))).toEqual(["@mod/metrics-log"]);
		expect(publishers(composedBy("nextgen-dev"))).toEqual(["@mod/metrics-prometheus"]);
	});

	it("leave client-credentials, sign-up, userinfo and introspection to the operator", () => {
		for (const name of ["nextgen-core", "nextgen-dev"]) {
			const modules = composedBy(name);
			for (const absent of [
				"@mod/client-credentials",
				"@mod/sign-up",
				"@mod/userinfo",
				"@mod/token-introspection",
			]) {
				expect(modules, `${name}: ${absent}`).not.toContain(absent);
			}
		}
		expect(composedBy("nextgen-core", { add: ["@mod/sign-up"] })).toContain("@mod/sign-up");
	});

	it("require, of the promises' names, claims 1 and 2 in the Core alone", () => {
		expect(named("nextgen-core").required).toEqual([
			promiseNames.newAuthorization,
			promiseNames.clientToken,
		]);
		expect(named("nextgen-front").required).toEqual([]);
		expect(named("nextgen-dev").required).toEqual([]);
	});

	it("tell, where an adapter never a default is chosen, its own line naming the promise it breaks", () => {
		for (const name of ["nextgen-core", "nextgen-dev"]) {
			const notices = noticesOf(selectionOf(named(name)));
			expect(notices).toHaveLength(1);
			expect(notices[0]).toContain(
				`@mod/transparency-local: Not recommended: \`${promiseNames.coreContained}\``,
			);
		}
		expect(noticesOf(selectionOf(named("nextgen-front")))).toEqual([]);
		// What is composed tells, however it came; an axis named that composes nothing does not.
		const added = selectionOf(named("nextgen-core"), {
			axes: { "@mod/transparency": "@mod/transparency" },
			add: ["@mod/transparency-local"],
		});
		expect(noticesOf(added)).toHaveLength(1);
		const unreached = selectionOf(named("nextgen-front"), {
			axes: { "@mod/transparency": "@mod/transparency-local" },
		});
		expect(noticesOf(unreached)).toEqual([]);
	});
});

describe("what the patterns reach, against the workspace's declarations", () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..");
	const workspace = readWorkspace(root);
	const byName = new Map(workspace.map((p) => [p.name, p]));

	it("declares no network word in a package of a pattern's dependencies that the pattern does not reach", () => {
		for (const pattern of patterns) {
			const within = new Set(reached(selectionOf(pattern)));
			const closure = new Set<string>();
			const walk = (name: string) => {
				if (closure.has(name) || !byName.has(name)) return;
				closure.add(name);
				for (const dep of Object.keys((byName.get(name)?.manifest.dependencies ?? {}) as object))
					walk(dep);
			};
			for (const name of within) walk(name);
			const unread = [...closure].filter(
				(n) => !within.has(n) && byName.get(n)?.manifest.network !== undefined,
			);
			expect(unread, pattern.name).toEqual([]);
		}
	});

	it("holds each fragment a pattern reaches to its section's schema, but at a REPLACE- placeholder", async () => {
		const within = new Set(patterns.flatMap((p) => reached(selectionOf(p))));
		const at = (tree: unknown, path: readonly PropertyKey[]) =>
			path.reduce<unknown>((t, k) => (t as Record<PropertyKey, unknown> | undefined)?.[k], tree);
		let read = 0;
		for (const name of within) {
			const p = byName.get(name);
			const file = p && join(p.dir, "config.example");
			if (!p || !file || !existsSync(file)) continue;
			const exports = (p.manifest.exports ?? {}) as Record<string, string>;
			const entry = exports["./module"] ?? (name === "@mod/kernel" ? exports["."] : undefined);
			if (!entry) continue;
			const loaded = await import(pathToFileURL(join(p.dir, entry)).href);
			const module = loaded.default as { name?: string; section?: unknown } | undefined;
			const schema = (module?.section ?? loaded.kernelSection) as {
				"~standard": {
					validate: (
						v: unknown,
					) => Promise<{ issues?: readonly { path?: readonly PropertyKey[] }[] }>;
				};
			};
			const section = module?.name ?? "kernel";
			const tree = (parse(readFileSync(file, "utf8")).toObject() as Record<string, unknown>)[
				section
			];
			const { issues = [] } = await schema["~standard"].validate(tree);
			const real = issues.filter((i) => !String(at(tree, i.path ?? [])).includes("REPLACE-"));
			expect(real, `${name}: ${JSON.stringify(real)}`).toEqual([]);
			read++;
		}
		expect(read).toBeGreaterThan(20);
	});

	it("names in each asks line only keys of a section the pattern reaches", async () => {
		const sections = await sectionsIn(workspace);
		const keysOf = new Map(
			sections.map((s) => [s.section, new Set(s.rows.map((r) => r.key.split(".")[1]))]),
		);
		for (const pattern of patterns) {
			const within = reached(selectionOf(pattern));
			const reachedSections = new Set(
				sections.filter((s) => within.includes(s.owner)).map((s) => s.section),
			);
			for (const name of within) {
				const manifest = (byName.get(name)?.manifest ?? {}) as Readonly<Record<string, unknown>>;
				const asks = (manifest.asks ?? []) as readonly (string | { line: string })[];
				for (const ask of asks) {
					const line = typeof ask === "string" ? ask : ask.line;
					for (const [, key] of line.matchAll(/`([a-z][a-z-]*\.[a-z][a-z.-]*)(?: = [^`]*)?`/g)) {
						const [section, first] = (key ?? "").split(".");
						if (!keysOf.has(section ?? "")) continue;
						expect(reachedSections.has(section ?? ""), `${pattern.name}: ${name}: ${key}`).toBe(
							true,
						);
						expect(keysOf.get(section ?? "")?.has(first ?? ""), `${name}: ${key}`).toBe(true);
					}
				}
			}
		}
	});
});

describe("create-app", () => {
	const io = () => {
		const said = { out: "", err: "" };
		return {
			said,
			io: {
				out: (t: string) => {
					said.out += t;
				},
				err: (t: string) => {
					said.err += t;
				},
			},
		};
	};

	it("lists the patterns, and refuses a usage it cannot read with 64", async () => {
		const listed = io();
		expect(await run(["--list"], listed.io)).toBe(0);
		expect(listed.said.out).toContain("nextgen-core: ");
		for (const args of [
			[],
			["t"],
			["t", "--pattern", "nextgen-x"],
			["t", "--pattern", "nextgen-core", "--axis", "http"],
			["a", "b", "--pattern", "nextgen-core"],
			["", "--pattern", "nextgen-core"],
			["--list", "--pattern", "nextgen-core"],
			["--bogus"],
		]) {
			expect(await run(args, io().io), args.join(" ")).toBe(64);
		}
	});

	it("refuses with 1, writing nothing, a target that holds anything or a composition it cannot make", async () => {
		const parent = await mkdtemp(join(tmpdir(), "create-app-cli-"));
		try {
			const held = join(parent, "held");
			await mkdir(held);
			await writeFile(join(held, "x"), "");
			expect(await run([held, "--pattern", "nextgen-core"], io().io)).toBe(1);
			expect(await readdir(held)).toEqual(["x"]);
			const empty = join(parent, "empty");
			const told = io();
			expect(
				await run([empty, "--pattern", "nextgen-core", "--add", "no-such-module"], told.io),
			).toBe(1);
			expect(told.said.err).toContain("@mod/no-such-module");
		} finally {
			await rm(parent, { recursive: true, force: true });
		}
	});
});
