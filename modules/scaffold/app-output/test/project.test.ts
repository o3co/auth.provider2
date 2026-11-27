import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type App, type Known, writeApp } from "../src/contract.ts";

let root = "";
const known = new Map<string, Known>();

/** A package of the fixture: its manifest, and its fragment where it has one. */
async function pkg(name: string, manifest: Record<string, unknown>, fragment?: string) {
	const dir = join(root, name.replace("/", "_"));
	await mkdir(dir, { recursive: true });
	await writeFile(join(dir, "package.json"), JSON.stringify({ name, ...manifest }));
	if (fragment !== undefined) await writeFile(join(dir, "config.example"), fragment);
	known.set(name, { name, dir, manifest: { name, ...manifest } });
}

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "app-output-"));
	await pkg(
		"@mod/kernel",
		{ kind: "common", asks: [{ line: "`kernel.deployment`: single or several.", decides: true }] },
		"kernel {\n\tdeployment = single\n}\n",
	);
	await pkg("@mod/config-files", { kind: "foundation" });
	await pkg("@mod/app-permissions", { kind: "foundation" });
	await pkg("@f/lib", { kind: "foundation", network: "outbound" });
	await pkg(
		"@f/web",
		{
			kind: "feature",
			network: "serves-http",
			asks: ["Web pages (`web.url`)."],
			appEntries: [{ script: "web-publish", shape: "call", contract: "web", member: "publish" }],
		},
		'web {\n\turl = "https://web.example.invalid"\n\thosts = ["a.example.invalid"]\n}\n',
	);
	await pkg("@mod/promises", { kind: "foundation" });
	await pkg("@f/helper", { kind: "foundation", network: "outbound" });
	await pkg("@f/serve", {
		kind: "companion",
		network: "serves-http",
		bin: { "f-serve": "./src/main.ts" },
		dependencies: { "@f/helper": "workspace:*" },
	});
	await pkg("@f/two-bins", { kind: "companion", bin: { a: "./a.ts", b: "./b.ts" } });
	await pkg("@f/clash", { kind: "companion", bin: { "web-publish": "./main.ts" } });
});

afterAll(async () => {
	await rm(root, { recursive: true, force: true });
});

const app = (over: Partial<App> = {}): App => ({
	modules: ["@f/web", "@mod/promises"],
	reached: ["@mod/kernel", "@mod/config-files", "@f/lib", "@f/web", "@mod/promises"],
	companions: ["@f/serve"],
	required: ["store-write"],
	known: (name) => known.get(name),
	dependency: (k) => `link:${k.dir}`,
	guide: { title: "fixture", use: "For the test.", card: "The fixture's card." },
	...over,
});

/** HOCON's optional substitution of a variable, as the configuration file reads it. */
const fromEnv = (variable: string) => `\${?${variable}}`;

const written = async (over: Partial<App> = {}) => {
	const target = await mkdtemp(join(root, "out-"));
	await writeApp(target, app(over));
	const read = (path: string) => readFile(join(target, path), "utf8");
	return { target, read };
};

describe("writeApp", () => {
	it("writes the manifest with the start, the entries and each companion's bin, depending on what is composed", async () => {
		const { read } = await written();
		const manifest = JSON.parse(await read("package.json"));
		expect(manifest.scripts).toEqual({
			start:
				"node --env-file-if-exists=.env --disable-proto=throw --disallow-code-generation-from-strings src/start.ts",
			"web-publish":
				"node --env-file-if-exists=.env --disable-proto=throw --disallow-code-generation-from-strings src/web-publish.ts",
			"f-serve": "node node_modules/@f/serve/src/main.ts",
		});
		expect(Object.keys(manifest.dependencies)).toEqual([
			"@mod/kernel",
			"@mod/config-files",
			"@mod/app-permissions",
			"@f/web",
			"@mod/promises",
			"@f/serve",
		]);
		expect(await read("src/main.ts")).toContain('import m0 from "@f/web/module";');
		// The start, which holds the entry under the permission model, and what it loads ahead of it.
		expect(await read("src/start.ts")).toContain('from "@mod/app-permissions"');
		expect(await read("src/permission-lines.ts")).toContain("node:permission-model:");
		expect(await read("src/web-publish.ts")).toContain("@f/web");
	});

	it("reads every scalar from its variable over what is reached, a package with no module too, and writes the promises required", async () => {
		const { read } = await written();
		const conf = await read("config/application.conf");
		expect(conf).toContain(`deployment = ${fromEnv("KERNEL_DEPLOYMENT")}`);
		expect(conf).toContain(`url = ${fromEnv("WEB_URL")}`);
		expect(conf).not.toMatch(/hosts =/);
		expect(conf).toContain('promises.required = ["store-write"]');
		expect(await read(".env.example")).toContain("# WEB_URL=https://web.example.invalid");
		expect(await read("config/local.conf.example")).toContain("# web.hosts = [");
	});

	it("writes no promises where none is required", async () => {
		const { read } = await written({ required: [], modules: ["@f/web"] });
		expect(await read("config/application.conf")).not.toContain("promises");
	});

	it("declares each process's words as the manifests state them, a companion's with those of what it depends on", async () => {
		const { read } = await written();
		expect(JSON.parse(await read("network.json"))).toEqual({
			processes: [
				{
					name: "app",
					start: "start",
					entries: ["web-publish"],
					words: [
						{ word: "outbound", from: "@f/lib" },
						{ word: "serves-http", from: "@f/web" },
					],
				},
				{
					name: "f-serve",
					start: "f-serve",
					words: [
						{ word: "serves-http", from: "@f/serve" },
						{ word: "outbound", from: "@f/helper" },
					],
				},
			],
		});
	});

	it("guides with what each reached package asks, the values decided and the promises required", async () => {
		const { read } = await written();
		const readme = await read("README.md");
		expect(readme).toContain("- Web pages (`web.url`).");
		expect(readme).toContain("- `kernel.deployment`: single or several.");
		expect(readme).toContain("- `store-write`");
		expect(readme).toContain("The fixture's card.");
	});

	it("writes permissions.json for the start: its code roots, what its packages declare with their sections, and whether it reaches the network", async () => {
		await pkg(
			"@f/files",
			{ kind: "adapter", permissions: { read: { keys: ["file", "keys.*.file"] } } },
			"files {\n\tfile = /run/a.pem\n\tkeys = [{ file = /run/k.pem }]\n}\n",
		);
		await pkg("@f/forking", { kind: "foundation", forks: { "src/a.ts": "src/a.mjs" } });
		const { read } = await written({
			reached: ["@mod/kernel", "@mod/config-files", "@f/files", "@f/forking", "@f/lib"],
			required: [],
			codeRoots: (packages) => [`/workspace/${packages.join("+")}`],
		});
		expect(JSON.parse(await read("permissions.json"))).toEqual({
			v: 1,
			processes: {
				start: {
					// Beyond the app's own directory, which the start adds: for the packages the start depends on.
					code: [
						"/workspace/@mod/kernel+@mod/config-files+@mod/app-permissions+@f/web+@mod/promises",
					],
					declared: [
						{
							package: "@f/files",
							section: "files",
							permissions: { read: { keys: ["file", "keys.*.file"] } },
							forks: false,
						},
						// It forks and declares nothing: its processes are granted always.
						{ package: "@f/forking", section: "", permissions: {}, forks: true },
					],
					network: true,
				},
			},
		});
	});

	it("refuses a declaration app-permissions does not take, a file key its fragment lacks, and child with no forks, naming the package", async () => {
		await pkg("@f/bad", { kind: "adapter", permissions: { files: [] } });
		await pkg(
			"@f/unheld",
			{ kind: "adapter", permissions: { read: { keys: ["path"] } } },
			"unheld {\n\tother = 1\n}\n",
		);
		await pkg(
			"@f/nofork",
			{ kind: "adapter", permissions: { child: { when: { key: "a", is: "b" } } } },
			"nofork {\n\ta = c\n}\n",
		);
		for (const [name, why] of [
			["@f/bad", /@f\/bad: permissions.files is no member/],
			["@f/unheld", /@f\/unheld: permissions names path, which its config.example does not hold/],
			["@f/nofork", /@f\/nofork: permissions names child, but it has no forks/],
		] as const) {
			const target = await mkdtemp(join(tmpdir(), "app-output-"));
			await expect(
				writeApp(target, app({ reached: ["@mod/kernel", name], required: [] })),
			).rejects.toThrow(why);
		}
	});

	it("refuses, writing nothing, a target that holds anything, promises required with none composed, and a companion of no one bin or whose bin is taken", async () => {
		const held = await mkdtemp(join(root, "held-"));
		await writeFile(join(held, "x"), "");
		await expect(writeApp(held, app())).rejects.toThrow(/not empty/);
		await expect(writeApp("", app())).rejects.toThrow(/no target named/);
		await expect(writeApp(join(held, "x"), app())).rejects.toThrow(/not a directory/);
		for (const [over, why] of [
			[{ reached: ["@mod/kernel", "@f/web"], modules: ["@f/web"] }, /promises required/],
			[{ companions: ["@f/lib"] }, /not a companion/],
			[{ companions: ["@f/two-bins"] }, /not one bin/],
			[{ companions: ["@f/clash"] }, /two scripts named web-publish/],
			[{ companions: ["@f/absent"] }, /not a package the caller knows/],
		] as const) {
			const target = await mkdtemp(join(root, "refused-"));
			await expect(writeApp(target, app(over)), String(why)).rejects.toThrow(why);
			expect(await readdir(target)).toEqual([]);
		}
	});
});
