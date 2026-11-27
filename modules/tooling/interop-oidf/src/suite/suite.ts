import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { type Docker, dockerWithin, docker as systemDocker } from "@mod/docker-client";
import { requestJson } from "../api/api.ts";
import { type Command, systemCommand } from "../commands/commands.ts";
import { composeOverride, projectOf } from "../compose/compose.ts";
import { reclaimOrphans } from "../orphans/orphans.ts";

/** Each command's own time: a setup step's within the plan's deadline, a stop's after it too. */
const budgetMs = {
	clone: 300_000,
	quick: 30_000,
	pip: 300_000,
	up: 600_000,
	logs: 60_000,
	down: 120_000,
} as const;

/** The suite's version, pinned: its release tag and the commit the tag names. */
export interface SuitePin {
	readonly tag: string;
	readonly commit: string;
	/** The Python packages its scripts import, each at one version. */
	readonly python: readonly string[];
}

/** The repository's pin, `suite-pin.json`, refused where it is not one. */
export async function suitePin(
	path: string | URL = new URL("../../suite-pin.json", import.meta.url),
): Promise<SuitePin> {
	const read: unknown = JSON.parse(await readFile(path, "utf8"));
	const { tag, commit, python } = (read ?? {}) as Record<string, unknown>;
	if (
		typeof tag !== "string" ||
		!/^release-v\d+\.\d+\.\d+$/.test(tag) ||
		typeof commit !== "string" ||
		!/^[0-9a-f]{40}$/.test(commit) ||
		!Array.isArray(python) ||
		python.length === 0 ||
		!python.every((p) => typeof p === "string" && /^[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9.]*$/.test(p))
	)
		throw new Error(
			"the suite's pin is a release tag, the 40-hex commit it names, and Python packages each at one version",
		);
	return { tag, commit, python };
}

/** The suite's public origin, as its own pages and the browser in it name it. */
export const suiteOrigin = "https://localhost.emobix.co.uk:8443";

const suiteMtlsOrigin = "https://localhost.emobix.co.uk:8444";

/** How long the suite may take to answer once started: as long as its own runner waits. */
const readyWithinMs = 360_000;

/** How the suite's containers reach this machine: the name, the address the front listens on, the IPv4 the name is given where Docker gives it none. */
export interface SuiteHost {
	readonly name: string;
	readonly listen: string;
	readonly mapped?: string;
}

/** Docker Desktop names this machine itself, in IPv4; on Linux the name is given the bridge's gateway. */
export async function hostForSuite(
	docker: Docker = systemDocker,
	platform: NodeJS.Platform = process.platform,
): Promise<SuiteHost> {
	if (platform === "darwin") return { name: "host.docker.internal", listen: "127.0.0.1" };
	const gateway = await docker(
		["network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"],
		dockerWithin.control,
	);
	return { name: "host.docker.internal", listen: gateway, mapped: gateway };
}

/**
 * The suite's stop failed, a start's own or a stop's: what stops the suite may still be needed, so
 * whatever holds it is kept.
 */
export class SuiteStopFailed extends AggregateError {}

/** The suite at its pinned version, started in `dir`: a directory of its own, removed when it stops. */
export interface Suite {
	/** The suite's scripts, as the pinned commit holds them. */
	readonly scripts: string;
	/** The Python that runs them, with their packages. */
	readonly python: string;
	/** The certificate its nginx answers with, as PEM in a file: for the app to trust. */
	readonly certificate: string;
	/** The suite's API, as a JSON GET from this machine. */
	api(path: string): Promise<unknown>;
	/** A request at the suite's API by any method it takes, a JSON body where given: its status as it comes, for the caller to judge, and its body. */
	call(
		method: "GET" | "POST" | "DELETE",
		path: string,
		body?: unknown,
	): Promise<{ status: number; body: unknown }>;
	stop(): Promise<void>;
}

/**
 * Starts the suite at `pin` in `dir`, each setup step held to its own time and to `signal`, the
 * plan's deadline. Its stop keeps the containers' states and logs in `log`, takes them down past the
 * deadline too, and removes `dir`, kept where they were not taken down (`SuiteStopFailed`).
 */
export async function startSuite(
	pin: SuitePin,
	dir: string,
	host: SuiteHost,
	log: string,
	/** The certificate its nginx answers with, as PEM: one naming `localhost.emobix.co.uk`. */
	tls: { readonly cert: string; readonly key: string },
	options: {
		/** The programs other than docker: git, Python and its packages. */
		readonly command?: Command;
		readonly docker?: Docker;
		/** The request the suite's API is asked by. */
		readonly request?: typeof requestJson;
		readonly signal?: AbortSignal;
	} = {},
): Promise<Suite> {
	const command = options.command ?? systemCommand;
	const docker = options.docker ?? systemDocker;
	const signal = options.signal;
	const request = options.request ?? requestJson;
	// Each request to the API is held to the plan's deadline besides its own time.
	const asked = signal ? { signal } : {};
	const source = join(dir, "suite");
	const compose = [
		"compose",
		"-p",
		projectOf(dir),
		"-f",
		join(source, "docker-compose-prebuilt.yml"),
		"-f",
		join(dir, "override.yml"),
	];
	/** A setup step: its own time, and the plan's deadline. */
	const step = (cmd: string, args: readonly string[], timeoutMs: number) =>
		command(cmd, args, { timeoutMs, ...(signal ? { signal } : {}) });
	const stop = async () => {
		const problems: unknown[] = [];
		/** What a command wrote to either stream, in the order written. */
		const kept = async (args: readonly string[]) =>
			docker([...compose, ...args], budgetMs.logs, { merged: true }).catch((error: unknown) => {
				problems.push(error);
				return "";
			});
		// Every container's state and log: a failed start is often one of them gone.
		const states = await kept(["ps", "--all", "--format", "{{.Service}} {{.State}} {{.Status}}"]);
		const logs = await kept(["logs", "--no-color"]);
		await writeFile(log, `${states}\n${logs}\n`).catch((error: unknown) => problems.push(error));
		const down = await docker([...compose, "down", "--volumes", "--remove-orphans"], budgetMs.down)
			.then(() => true)
			.catch((error: unknown) => {
				problems.push(error);
				return false;
			});
		// What stops the suite stays while its containers may run.
		if (down)
			await rm(dir, { recursive: true, force: true }).catch((error: unknown) =>
				problems.push(error),
			);
		if (problems.length > 0)
			throw new SuiteStopFailed(
				problems,
				`the suite's stop failed${down ? "" : `; its compose files stay in ${dir}`}`,
			);
	};
	await mkdir(dir, { recursive: true });
	let composed = false;
	try {
		await reclaimOrphans(docker, join(dirname(log), "reclaimed"));
		await step(
			"git",
			[
				"clone",
				"--quiet",
				"--depth",
				"1",
				"--branch",
				pin.tag,
				"https://gitlab.com/openid/conformance-suite.git",
				source,
			],
			budgetMs.clone,
		);
		const { stdout: head } = await step("git", ["-C", source, "rev-parse", "HEAD"], budgetMs.quick);
		if (head.trim() !== pin.commit) {
			throw new Error(
				`the suite's tag ${pin.tag} names ${head.trim()}, not the pinned ${pin.commit}`,
			);
		}
		const files = { cert: join(dir, "nginx-cert.pem"), key: join(dir, "nginx-key.pem") };
		await writeFile(files.cert, tls.cert);
		await writeFile(files.key, tls.key, { mode: 0o600 });
		await writeFile(
			join(dir, "override.yml"),
			composeOverride(host, {
				tag: pin.tag,
				origins: { base: suiteOrigin, mtls: suiteMtlsOrigin },
				tls: files,
			}),
		);
		const venv = join(dir, "python");
		await step("python3", ["-m", "venv", venv], budgetMs.quick);
		await step(join(venv, "bin", "pip"), ["install", "--quiet", ...pin.python], budgetMs.pip);
		// From here the containers may run: a failure stops them by Compose.
		composed = true;
		await docker([...compose, "up", "--detach", "--quiet-pull"], budgetMs.up, {
			...(signal ? { signal } : {}),
		});
		const deadline = Date.now() + readyWithinMs;
		// Only the harness's certificate is trusted, by its fingerprint: an nginx answering with its own fails.
		const ca = tls.cert;
		for (;;) {
			signal?.throwIfAborted();
			try {
				if ((await request("GET", `${suiteOrigin}/api/plan?length=1`, ca, asked)).status === 200)
					break;
			} catch {}
			if (Date.now() > deadline)
				throw new Error(`the suite did not answer within ${readyWithinMs / 1000}s`);
			await sleep(2_000, signal);
		}
		return {
			scripts: join(source, "scripts"),
			python: join(venv, "bin", "python"),
			certificate: files.cert,
			api: async (path) => {
				const answer = await request("GET", `${suiteOrigin}/${path}`, ca, asked);
				if (answer.status !== 200)
					throw new Error(`the suite answered ${answer.status} to ${path}`);
				return answer.body;
			},
			call: (method, path, body) =>
				request(method, `${suiteOrigin}/${path}`, ca, {
					...asked,
					...(body === undefined ? {} : { body }),
				}),
			stop,
		};
	} catch (error) {
		// Before Compose was asked for a container, there is nothing to stop: what was prepared goes.
		if (!composed) {
			const removed = await rm(dir, { recursive: true, force: true }).then(
				() => undefined,
				(failed: unknown) => failed,
			);
			if (removed !== undefined)
				throw new AggregateError([error, removed], `${String(error)}; and ${dir} stays`);
			throw error;
		}
		// The start's failure first, then each of the stop's.
		const stopped = await stop().then(
			() => undefined,
			(failed: unknown) => failed,
		);
		if (stopped !== undefined)
			throw new SuiteStopFailed(
				[error, ...(stopped instanceof AggregateError ? stopped.errors : [stopped])],
				`${String(error)}; and ${stopped instanceof Error ? stopped.message : String(stopped)}`,
			);
		throw error;
	}
}

/** Waits `ms`, or less where `signal` aborts. */
const sleep = (ms: number, signal?: AbortSignal) =>
	new Promise<void>((resolve, reject) => {
		const timer = setTimeout(resolve, ms);
		signal?.addEventListener(
			"abort",
			() => {
				clearTimeout(timer);
				reject(signal.reason);
			},
			{ once: true },
		);
	});
