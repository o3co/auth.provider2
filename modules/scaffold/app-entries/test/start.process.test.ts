import { spawn, spawnSync } from "node:child_process";
import {
	mkdir,
	mkdtemp,
	readFile,
	realpath,
	rename,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	appPermissions,
	configFiles,
	kernel,
	permissionLinesSource,
	startSource,
} from "../src/contract.ts";

// The app's start, generated and run as `run` runs it, over the real config-files, kernel and
// app-permissions, and an entry of the test's own that tells what it may read.

const modules = join(import.meta.dirname, "..", "..", "..");
const sources: Record<string, string> = {
	[kernel]: join(modules, "foundation", "kernel", "src", "contract.ts"),
	[configFiles]: join(modules, "foundation", "config-files", "src", "contract.ts"),
	[appPermissions]: join(modules, "foundation", "app-permissions", "src", "contract.ts"),
};
const importOf = (name: string) => pathToFileURL(sources[name] ?? name).href;

// The entry: its pid and flags, whether it reads the file its section names, one outside every grant
// and one a link inside the app names; where asked, what a plain node child reads, or (NOISE) a refused
// read and an exit at once behind a full standard error.
const entry = `import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const tried = (path) => { try { readFileSync(path); return "read"; } catch (error) { return error.code; } };
if (process.env.NOISE) { process.stderr.write(\`\${"x".repeat(Number(process.env.NOISE))}\\n\`); for (let i = 0; i < 3000; i++) tried(process.env.OUTSIDE); process.exit(0); }
const read = \`try { require("node:fs").readFileSync(\${JSON.stringify(process.env.OUTSIDE)}); console.log("read"); } catch (error) { console.log(error.code); }\`;
const started = () => { try { return spawnSync(process.execPath, ["-e", read], { encoding: "utf8" }).stdout.trim(); } catch (error) { return \`spawn \${error.code}\`; } };
const child = process.env.CHILD ? started() : undefined;
console.log(JSON.stringify({ pid: process.pid, execArgv: process.execArgv, named: tried(process.env.NAMED), token: tried(process.env.TOKEN_FILE), outside: tried(process.env.OUTSIDE), linked: tried(process.env.LINKED), child }));
`;

let app: string;
let outside: string;
beforeAll(async () => {
	// Real paths: Node reads the code by its real path, and a grant is checked by the path as named.
	app = await realpath(await mkdtemp(join(tmpdir(), "start-app-")));
	outside = await realpath(await mkdtemp(join(tmpdir(), "start-outside-")));
	await mkdir(join(app, "src"));
	await mkdir(join(app, "config"));
	await writeFile(join(app, "src", "start.ts"), await startSource(importOf));
	await writeFile(join(app, "src", "permission-lines.ts"), await permissionLinesSource());
	await writeFile(join(app, "src", "main.ts"), entry);
	await writeFile(join(outside, "named.pem"), "named");
	await writeFile(join(outside, "token"), "token");
	await writeFile(join(outside, "secret"), "secret");
	// A link inside the app to a file outside every grant: the reach a grant gives, which the cards say.
	await symlink(join(outside, "secret"), join(app, "linked"));
	// An execve that fails, as one refused by the system would.
	await writeFile(
		join(app, "src", "no-execve.mjs"),
		'process.execve = () => { throw Object.assign(new Error("refused"), { code: "EACCES" }); };\n',
	);
	// A platform with no execve in place (Windows), as the start tells one.
	await writeFile(
		join(app, "src", "windows.mjs"),
		'Object.defineProperty(process, "platform", { value: "win32" });\n',
	);
	await writeFile(
		join(app, "config", "application.conf"),
		`store { file = "${join(outside, "named.pem")}", file = \${?STORE_FILE}, mode = \${?STORE_MODE} }\n`,
	);
	// A variable-named file, set where the operator sets one: the app's .env.
	await writeFile(join(app, ".env"), `TOKEN_FILE=${join(outside, "token")}\n`);
	const start = {
		code: [app, ...Object.values(sources).map((file) => join(file, "..", ".."))],
		network: false,
		declared: [
			{
				package: "@t/store",
				section: "store",
				forks: true,
				permissions: {
					read: {
						keys: ["file"],
						env: [{ name: "TOKEN_FILE" }, { name: "SHARED_FILE", default: "~/shared", home: true }],
					},
					child: { when: { key: "mode", is: "fork" } },
				},
			},
		],
	};
	await writeFile(join(app, "permissions.json"), JSON.stringify({ v: 1, processes: { start } }));
});
afterAll(async () => {
	await rm(app, { recursive: true, force: true });
	await rm(outside, { recursive: true, force: true });
});

/** The start as `run` runs it: its .env read, and the two hardening flags. */
/** The start's command line as `run` writes it, with `nodeArgs` before its file. */
const lineOf = (args: readonly string[], nodeArgs: readonly string[] = []) => [
	"--env-file-if-exists=.env",
	"--disable-proto=throw",
	"--disallow-code-generation-from-strings",
	...nodeArgs,
	"src/start.ts",
	...args,
];
const envOf = (env: Record<string, string>) => ({
	PATH: process.env.PATH ?? "",
	HOME: process.env.HOME ?? "",
	NAMED: join(outside, "named.pem"),
	OUTSIDE: join(outside, "secret"),
	LINKED: join(app, "linked"),
	...env,
});
/** The start run now, as `run` runs it, and what its entry and preload told. */
const startedNow = (
	env: Record<string, string> = {},
	args: readonly string[] = [],
	nodeArgs: readonly string[] = [],
) => {
	const run = spawnSync(process.execPath, lineOf(args, nodeArgs), {
		cwd: app,
		encoding: "utf8",
		env: envOf(env),
	});
	const told =
		run.stdout.trim() === "" || args.includes("--print")
			? undefined
			: JSON.parse(run.stdout.trim().split("\n").at(-1) ?? "{}");
	const events = run.stderr
		.split("\n")
		.filter((line) => line.startsWith("{"))
		.map((line) => JSON.parse(line));
	return { ...run, told, events };
};

/**
 * The start as `startedNow` runs it, once for each environment and arguments: the tests that ask the
 * same run read the one result (frozen: they only read it), so the file spawns no run twice. Each case
 * asks one run of its own at most, so its cost is one start whichever cases ran before it. A test that
 * changes the app's files between runs asks `startedNow`.
 */
const runs = new Map<string, ReturnType<typeof startedNow>>();
const started = (
	env: Record<string, string> = {},
	args: readonly string[] = [],
	nodeArgs: readonly string[] = [],
) => {
	const key = JSON.stringify([Object.entries(env).sort(), args, nodeArgs]);
	const kept = runs.get(key) ?? Object.freeze(startedNow(env, args, nodeArgs));
	// A run a signal ended or that never spawned is the machine's, not the start's: never kept.
	if (kept.status !== null && kept.error === undefined) runs.set(key, kept);
	return kept;
};

describe("the app's start", () => {
	it("audits by default: unset, the entry runs under --permission-audit", () => {
		const run = started();
		expect(run.status).toBe(0);
		expect(run.told.execArgv).toContain("--permission-audit");
		expect(run.told).toMatchObject({ named: "read", outside: "read" });
	});

	it("holds the entry under enforce: the files its packages name are read, one outside every grant is refused and told", () => {
		const run = started({ APP_PERMISSION: "enforce" });
		expect(run.status).toBe(0);
		expect(run.told).toMatchObject({ named: "read", token: "read", outside: "ERR_ACCESS_DENIED" });
		// In this process: the same pid the start was run as, the flags of run carried on.
		expect(run.told.pid).toBe(run.pid);
		expect(run.told.execArgv).toEqual(
			expect.arrayContaining([
				"--disable-proto=throw",
				"--disallow-code-generation-from-strings",
				"--permission",
			]),
		);
		expect(run.told.execArgv.some((flag: string) => flag.startsWith("--allow-fs-write"))).toBe(
			false,
		);
		expect(run.events).toContainEqual(
			expect.objectContaining({ event: "app-permissions.event", kind: "fs" }),
		);
	});

	it("audits with the same grants: the outside read goes through and is told", () => {
		const audit = started({ APP_PERMISSION: "audit" });
		expect(audit.told).toMatchObject({ named: "read", outside: "read" });
		expect(audit.events.some((event) => event.kind === "fs")).toBe(true);
	});

	it("holds nothing off, and tells nothing", () => {
		const off = started({ APP_PERMISSION: "off" });
		expect(off.told).toMatchObject({ outside: "read" });
		expect(off.told.execArgv).not.toContain("--permission");
		expect(off.events).toEqual([]);
	});

	it("grants child processes where a package's condition holds, and warns of it; a plain node child is held by the same grants", () => {
		const held = started({ APP_PERMISSION: "enforce", STORE_MODE: "fork", CHILD: "1" });
		expect(held.stderr).toContain(
			"warn app-permissions: child processes are allowed, for @t/store",
		);
		// The child, started plainly, inherits the grants: it runs, and its read outside them is refused.
		expect(held.told.child).toBe("ERR_ACCESS_DENIED");
		expect(held.told.execArgv).toContain("--allow-child-process");
	});

	it("grants no child process where no package's condition holds: the entry starts none", () => {
		const none = started({ APP_PERMISSION: "enforce", CHILD: "1" });
		expect(none.told.execArgv).not.toContain("--allow-child-process");
		expect(none.told.child).toBe("spawn ERR_ACCESS_DENIED");
		expect(none.stderr).not.toContain("child processes are allowed");
	});

	it("refuses with 78 a mode it does not take, never echoing it, before the entry starts", () => {
		const mode = started({ APP_PERMISSION: "loose-please" });
		expect(mode.status).toBe(78);
		expect(mode.stderr).toContain("refused APP_PERMISSION: one of enforce, audit or off");
		expect(mode.stderr).not.toContain("loose-please");
		expect(mode.stdout).toBe("");
	});

	it("refuses with 78 a configuration that cannot load, before the entry starts", () => {
		const config = started({ APP_CONFIG: "config/none.conf" });
		expect(config.status).toBe(78);
		expect(config.stderr).toMatch(/refused config\/none\.conf: cannot read the configuration file/);
		expect(config.stdout).toBe("");
	});

	it("prints the command it would run, for a configuration, without running it", () => {
		const run = started({}, ["--print"]);
		expect(run.status).toBe(0);
		const argv = JSON.parse(run.stdout) as string[];
		expect(argv).toEqual(
			expect.arrayContaining([
				"--permission-audit",
				`--allow-fs-read=${join(outside, "named.pem")}`,
			]),
		);
		expect(argv.at(-1)).toBe(join(app, "src", "main.ts"));
	});

	it("writes every event whole before an exit right after them, behind a slow reader of a full pipe, and lives on", async () => {
		for (const mode of ["audit", "enforce"])
			for (const before of ["0", "10", String(1 << 21)]) {
				const child = spawn(process.execPath, lineOf([]), {
					cwd: app,
					env: envOf({ APP_PERMISSION: mode, NOISE: before }),
				});
				let stderr = "";
				child.stderr.on("data", (chunk) => {
					stderr += chunk;
				});
				// Read only after a while, as a slow reader holds the pipe full.
				child.stderr.pause();
				setTimeout(() => child.stderr.resume(), 1000);
				const code = await new Promise((closed) => child.on("close", closed));
				// Records as a reader reads them: whole JSON lines, none inside another line.
				const events = stderr
					.split("\n")
					.filter((line) => line.startsWith('{"event":"app-permissions.event"'))
					.filter((line) => JSON.parse(line).event === "app-permissions.event").length;
				expect([mode, before, code, events]).toEqual([mode, before, 0, 3000]);
				expect(stderr).not.toContain("EAGAIN");
			}
	}, 60_000);

	it.each(["audit", "enforce"])("says first how the entry is held, under %s", (mode) => {
		expect(started({ APP_PERMISSION: mode }).events[0]).toEqual({
			event: "app-permissions.held",
			mode,
		});
	});

	it("says nothing of how the entry is held off", () => {
		expect(started({ APP_PERMISSION: "off" }).events).toEqual([]);
	});

	it("says none, loaded where no permission model is on: an entry run unheld never passes for held", () => {
		const unheld = spawnSync(
			process.execPath,
			["--import", "./src/permission-lines.ts", "-e", ""],
			{
				cwd: app,
				encoding: "utf8",
				env: envOf({}),
			},
		);
		expect(unheld.stderr).toBe(`{"event":"app-permissions.held","mode":"none"}\n`);
	});

	it("takes `~/` where the reader expands it as the home its readers take: USERPROFILE where HOME is unset", () => {
		const argv = JSON.parse(
			started({ HOME: "", USERPROFILE: outside }, ["--print"]).stdout,
		) as string[];
		expect(argv).toContain(`--allow-fs-read=${join(outside, "shared")}`);
	});

	it("takes `~/` as HOME where it is set", () => {
		const home = JSON.parse(
			started({ HOME: app, USERPROFILE: outside }, ["--print"]).stdout,
		) as string[];
		expect(home).toContain(`--allow-fs-read=${join(app, "shared")}`);
	});

	it.each(["off", "audit", "enforce"])(
		"refuses, %s, an entry it cannot start in place, which never runs",
		(mode) => {
			const run = started({ APP_PERMISSION: mode }, [], ["--import", "./src/no-execve.mjs"]);
			expect(run.status).toBe(78);
			expect(run.stderr).toContain("refused start: the entry could not be started in place");
			expect(run.stdout).toBe("");
		},
	);

	it("names a value it cannot grant by its key, never the path", () => {
		const run = started({ APP_PERMISSION: "enforce", STORE_FILE: join(outside, "a*b.pem") });
		expect(run.status).toBe(78);
		expect(run.stderr).toContain(
			"refused store.file: names a path holding * or ,, which Node cannot grant",
		);
		expect(run.stderr).not.toContain("a*b.pem");
		expect(run.stdout).toBe("");
	});

	it.each([
		["missing", undefined, "refused permissions.json: it cannot be read: generate the app again"],
		[
			"no JSON",
			"{",
			"refused permissions.json: permissions.json is no JSON: generate the app again",
		],
		[
			"with no start",
			'{"v":1,"processes":{}}',
			"refused permissions.json: it holds no start: generate the app again",
		],
	] as const)(
		"refuses permissions.json %s, before the entry starts",
		async (_named, text, said) => {
			const file = join(app, "permissions.json");
			const kept = await readFile(file, "utf8");
			try {
				if (text === undefined) await rename(file, `${file}.kept`);
				else await writeFile(file, text);
				const run = startedNow({ APP_PERMISSION: "enforce" });
				expect(run.status).toBe(78);
				expect(run.stderr).toContain(said);
				expect(run.stdout).toBe("");
			} finally {
				// Restored whatever failed: the kept text written back, the moved file let go.
				await writeFile(file, kept);
				await rm(`${file}.kept`, { force: true });
			}
		},
	);

	it("reads what a link inside the app names, outside every grant: the reach a grant gives", () => {
		expect(started({ APP_PERMISSION: "enforce" }).told).toMatchObject({
			linked: "read",
			outside: "ERR_ACCESS_DENIED",
		});
	});

	it("prints the command off would run without running it", () => {
		const run = started({ APP_PERMISSION: "off" }, ["--print"]);
		expect(run.status).toBe(0);
		const argv = JSON.parse(run.stdout) as string[];
		expect(argv.some((flag) => flag.startsWith("--permission"))).toBe(false);
		expect(argv).toContain(join(app, "src", "main.ts"));
	});

	it("where no entry starts in place (Windows), runs it here when off", () => {
		const off = started({ APP_PERMISSION: "off" }, [], ["--import", "./src/windows.mjs"]);
		expect(off.status).toBe(0);
		expect(off.told.pid).toBe(off.pid);
		expect(off.told.execArgv.some((flag: string) => flag.startsWith("--permission"))).toBe(false);
	});

	it.each(["audit", "enforce"])("where no entry starts in place (Windows), refuses %s", (mode) => {
		const held = started({ APP_PERMISSION: mode }, [], ["--import", "./src/windows.mjs"]);
		expect(held.status).toBe(78);
		expect(held.stderr).toContain(
			"refused APP_PERMISSION: this platform starts no entry in place: set it to off",
		);
	});
});
