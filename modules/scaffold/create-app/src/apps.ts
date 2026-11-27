/** Generated apps run as an operator runs them: the generated entry in a process of its own, linked to the workspace. */
import { type ChildProcess, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generate, type Plan } from "./contract.ts";

/** A port free now, for an app to listen on. */
export const freePort = () =>
	new Promise<number>((done) => {
		const server = createServer().listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			server.close(() => done(port));
		});
	});

/** A generated app in a temporary directory, each dependency linked as the manifest's `link:` names it. */
export async function generated(plan: Plan) {
	const parent = await mkdtemp(join(tmpdir(), "create-app-"));
	const dir = join(parent, "app");
	const notices = await generate(dir, plan);
	const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
	for (const [name, spec] of Object.entries(manifest.dependencies as Record<string, string>)) {
		const link = join(dir, "node_modules", name);
		await mkdir(join(link, ".."), { recursive: true });
		await symlink(spec.replace(/^link:/, ""), link);
	}
	return { dir, notices, manifest, remove: () => rm(parent, { recursive: true, force: true }) };
}

/** A run of a script of the app: its output so far, its exit, and a way to stop it. */
export interface Running {
	readonly out: () => string;
	readonly exited: Promise<number | null>;
	stop(): Promise<number | null>;
}

/** How long a run told to stop may take before it is killed. */
const stopWithinMs = 10_000;

/**
 * Runs a file of the app with the configuration given in its local layer, first, over its own
 * `application.conf` (`APP_CONFIG`, which `env` cannot change), and an environment of the run's
 * `PATH` and what `env` gives alone: no other variable of the run is inherited. The local layer is a
 * file of the app's directory, so one configuration is run in a directory at a time.
 */
export async function running(
	dir: string,
	file: string,
	config: unknown,
	env: Readonly<Record<string, string>> = {},
	args: readonly string[] = [],
	nodeArgs: readonly string[] = [],
): Promise<Running> {
	await writeFile(join(dir, "config", "local.conf"), JSON.stringify(config));
	const child: ChildProcess = spawn(process.execPath, [...nodeArgs, file, ...args], {
		cwd: dir,
		env: {
			PATH: process.env.PATH ?? "",
			...env,
			APP_CONFIG: "config/local.conf,config/application.conf",
		},
		stdio: ["ignore", "pipe", "pipe"],
	});
	let out = "";
	child.stdout?.on("data", (c) => {
		out += c;
	});
	child.stderr?.on("data", (c) => {
		out += c;
	});
	// A process that cannot start ends the run, its error in the output, never an unhandled event.
	const exited = new Promise<number | null>((done) => {
		child.on("exit", (code) => done(code));
		child.on("error", (error) => {
			out += `${String(error)}\n`;
			done(null);
		});
	});
	return {
		out: () => out,
		exited,
		/** SIGTERM, its own drain; SIGKILL past `stopWithinMs`. */
		stop: async () => {
			child.kill("SIGTERM");
			const late = setTimeout(() => child.kill("SIGKILL"), stopWithinMs);
			const code = await exited;
			clearTimeout(late);
			return code;
		},
	};
}

/**
 * Runs a script of the app as its manifest writes it (`node`, its flags, its file), with the
 * configuration and environment `running` gives: the app's own command line, its flags among it.
 */
export async function scripted(
	dir: string,
	script: string,
	config: unknown,
	env: Readonly<Record<string, string>> = {},
	args: readonly string[] = [],
): Promise<Running> {
	const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
	const line = String(manifest.scripts?.[script] ?? "");
	const [node, ...rest] = line.split(" ");
	const file = rest.at(-1);
	if (node !== "node" || file === undefined) throw new Error(`${script}: not a node script`);
	return running(dir, file, config, env, args, rest.slice(0, -1));
}

/** Whether something listens on the port within the time given; false at once where the run exits. */
export async function listening(port: number, run: Running, withinMs: number): Promise<boolean> {
	let ended = false;
	void run.exited.then(() => {
		ended = true;
	});
	const until = Date.now() + withinMs;
	while (!ended && Date.now() < until) {
		const up = await new Promise<boolean>((done) => {
			const socket = connect(port, "127.0.0.1", () => {
				socket.destroy();
				done(true);
			});
			socket.on("error", () => done(false));
		});
		if (up) return true;
		await new Promise((r) => setTimeout(r, 100));
	}
	return false;
}

/** A key's variable, as the generated configuration file reads it: the path joined by `_`, upper-cased, `-` as `_`. */
const variableOf = (path: readonly string[]) => path.join("_").toUpperCase().replaceAll("-", "_");

/**
 * A configuration split as an operator writes it for the generated app: each scalar whose variable
 * `.env.example` names goes in the environment, everything else in the local layer.
 */
export async function asOperator(dir: string, config: Record<string, unknown>) {
	const example = await readFile(join(dir, ".env.example"), "utf8");
	const variables = new Set([...example.matchAll(/^# ([A-Z][A-Z0-9_]*)=/gm)].map((m) => m[1]));
	const env: Record<string, string> = {};
	const local = (tree: Record<string, unknown>, path: readonly string[]): Record<string, unknown> =>
		Object.fromEntries(
			Object.entries(tree).flatMap(([key, value]) => {
				const at = [...path, key];
				if (typeof value === "object" && value !== null && !Array.isArray(value)) {
					const inner = local(value as Record<string, unknown>, at);
					return Object.keys(inner).length === 0 ? [] : [[key, inner]];
				}
				const variable = variableOf(at);
				if (typeof value !== "object" && variables.has(variable)) {
					env[variable] = String(value);
					return [];
				}
				return [[key, value]];
			}),
		);
	return { env, local: local(config, []) };
}
