import { existsSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Docker } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import type { Command } from "../../commands/commands.ts";
import { hostForSuite, SuiteStopFailed, startSuite, suitePin } from "../suite.ts";

const pin = { tag: "release-v1.2.3", commit: "c0ffee", python: ["httpx==1"] };
const host = { name: "host.docker.internal", listen: "127.0.0.1" };
const tls = { cert: "PEM:cert", key: "PEM:key" };

/** The programs other than docker: git answers the pinned commit unless `head` says another. */
function programs(head = pin.commit) {
	const calls: { cmd: string; args: readonly string[]; signal?: AbortSignal }[] = [];
	const command: Command = async (cmd, args, options) => {
		calls.push({ cmd, args, ...(options.signal ? { signal: options.signal } : {}) });
		return { stdout: cmd === "git" && args[0] === "-C" ? `${head}\n` : "" };
	};
	return { command, calls };
}

/** A docker client that answers as `answer` says, keeping each call; one it does not know answers nothing. */
function dockers(
	answer: (args: readonly string[], signal?: AbortSignal) => Promise<string> | string = () => "",
) {
	const calls: {
		args: readonly string[];
		within: number;
		merged: boolean;
		signal?: AbortSignal;
	}[] = [];
	const docker: Docker = async (args, within, told) => {
		calls.push({
			args,
			within,
			merged: told?.merged ?? false,
			...(told?.signal ? { signal: told.signal } : {}),
		});
		return answer(args, told?.signal);
	};
	return { docker, calls };
}

const isCompose = (args: readonly string[], word: string) =>
	args[0] === "compose" && args.includes(word);

describe("the suite's pin", () => {
	it("is the repository's: a release tag and the commit it names, its Python packages each at one version", async () => {
		const read = await suitePin();
		expect(read.tag).toMatch(/^release-v\d+\.\d+\.\d+$/);
		expect(read.commit).toMatch(/^[0-9a-f]{40}$/);
		expect(read.python.length).toBeGreaterThan(0);
	});

	it("refuses a pin that names a branch, a short commit or a package at no one version", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-pin-"));
		const commit = "246b2c14b8562012b02d0ac462d667fe49e1a937";
		for (const bad of [
			{ tag: "master", commit, python: ["httpx==0.28.1"] },
			{ tag: "release-v5.3.5", commit: "246b2c1", python: ["httpx==0.28.1"] },
			{ tag: "release-v5.3.5", commit, python: ["httpx"] },
			{ tag: "release-v5.3.5", commit, python: ["httpx>=0.28"] },
			{ tag: "release-v5.3.5", commit },
			{ tag: "release-v5.3.5", commit, python: [] },
		]) {
			const path = join(dir, "pin.json");
			await writeFile(path, JSON.stringify(bad));
			await expect(suitePin(path)).rejects.toThrow("the suite's pin is");
		}
	});
});

describe("the machine the suite's containers reach", () => {
	it("is Docker Desktop's own name on a Mac, and the bridge's gateway in IPv4 on Linux", async () => {
		const { docker, calls } = dockers(() => "172.17.0.1");
		expect(await hostForSuite(docker, "darwin")).toEqual({
			name: "host.docker.internal",
			listen: "127.0.0.1",
		});
		expect(calls).toEqual([]);
		expect(await hostForSuite(docker, "linux")).toEqual({
			name: "host.docker.internal",
			listen: "172.17.0.1",
			mapped: "172.17.0.1",
		});
		expect(calls.map((c) => c.args.slice(0, 3))).toEqual([["network", "inspect", "bridge"]]);
	});
});

describe("the suite's start and stop, held to their time and leaving nothing behind", () => {
	it("gives up at the plan's deadline on a step that hangs, and still stops what it started", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-start-"));
		const { command } = programs();
		const { docker, calls } = dockers(
			(args, signal) =>
				new Promise<string>((resolve, reject) => {
					if (isCompose(args, "up")) {
						signal?.addEventListener("abort", () => reject(new Error("aborted")));
						return;
					}
					resolve("");
				}),
		);
		const started = startSuite(pin, join(dir, "suite"), host, join(dir, "suite.log"), tls, {
			command,
			docker,
			signal: AbortSignal.timeout(200),
		});
		await expect(started).rejects.toThrow();
		// The stop runs past the deadline, by budgets of its own: its log is kept, and the containers go.
		for (const word of ["ps", "logs", "down"]) {
			const step = calls.find((c) => isCompose(c.args, word));
			expect(step, word).toBeDefined();
			expect(step?.signal, word).toBeUndefined();
			expect(step?.within, word).toBeGreaterThan(0);
		}
	});

	it("says its stop failed, and keeps what stops the suite, where the containers could not be taken down", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-stop-"));
		const suiteDir = join(dir, "suite");
		const { command } = programs();
		// The suite comes up, never answers before the deadline, and the daemon then fails to take it down.
		const { docker } = dockers((args) => {
			if (isCompose(args, "down")) throw new Error("the daemon did not answer");
			return "";
		});
		const error = await startSuite(pin, suiteDir, host, join(dir, "suite.log"), tls, {
			command,
			docker,
			request: async () => ({ status: 503, body: "" }),
			signal: AbortSignal.timeout(300),
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		// Told as the suite's stop failing, for the caller to keep what stops it.
		expect(error).toBeInstanceOf(SuiteStopFailed);
		const told =
			error instanceof AggregateError ? error.errors.map(String).join("\n") : String(error);
		expect(String(error)).toContain(`its compose files stay in ${suiteDir}`);
		expect(told).toContain("the daemon did not answer");
		expect(existsSync(join(suiteDir, "override.yml"))).toBe(true);
	});

	it("keeps every container's state and what it wrote to either stream in the suite's log", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-log-"));
		const { command } = programs();
		const { docker, calls } = dockers((args) => {
			// The containers fail to come up: the start fails, and its stop keeps the log.
			if (isCompose(args, "up")) throw new Error("server-1 exited");
			// Every container, a stopped one too, as `--all` asks.
			if (isCompose(args, "ps")) return args.includes("--all") ? "server exited Exited (1)" : "";
			// The client's answer with both streams merged, as `merged` asks it.
			if (isCompose(args, "logs")) return "server-1 | started\nserver-1 | OutOfMemoryError";
			return "";
		});
		await expect(
			startSuite(pin, join(dir, "suite"), host, join(dir, "suite.log"), tls, { command, docker }),
		).rejects.toThrow("server-1 exited");
		const log = await readFile(join(dir, "suite.log"), "utf8");
		expect(log).toContain("server exited Exited (1)\n");
		expect(log).toContain("server-1 | started\nserver-1 | OutOfMemoryError\n");
		for (const word of ["ps", "logs"])
			expect(calls.filter((c) => isCompose(c.args, word)).map((c) => c.merged)).toEqual([true]);
	});

	it("removes what it prepared, and asks nothing of Compose, where it fails before any container was started", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-early-"));
		const suiteDir = join(dir, "suite");
		// The tag names another commit; and the daemon would fail any Compose command.
		const { command } = programs("deadbeef");
		const { docker, calls } = dockers((args) => {
			if (args[0] === "compose") throw new Error("the daemon did not answer");
			return "";
		});
		const error = await startSuite(pin, suiteDir, host, join(dir, "suite.log"), tls, {
			command,
			docker,
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(String(error)).toContain("not the pinned");
		expect(error).not.toBeInstanceOf(SuiteStopFailed);
		expect(calls.some((c) => c.args[0] === "compose")).toBe(false);
		expect(existsSync(suiteDir)).toBe(false);
	});

	it("clones the pinned tag, composes its own project beside the suite's file, and holds each setup step to the deadline", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-steps-"));
		const suiteDir = join(dir, "suite");
		const { command, calls: ran } = programs();
		const { docker, calls } = dockers();
		const deadline = new AbortController().signal;
		const suite = await startSuite(pin, suiteDir, host, join(dir, "suite.log"), tls, {
			command,
			docker,
			request: async () => ({ status: 200, body: {} }),
			signal: deadline,
		});
		const override = await readFile(join(suiteDir, "override.yml"), "utf8");
		expect(override).toContain(`conformance-suite:${pin.tag}\n`);
		await suite.stop();
		expect(ran[0]?.args).toEqual(expect.arrayContaining(["--branch", pin.tag]));
		for (const r of ran) expect(r.signal).toBe(deadline);
		const up = calls.find((c) => isCompose(c.args, "up"));
		expect(up?.signal).toBe(deadline);
		expect(up?.args.slice(0, 7)).toEqual([
			"compose",
			"-p",
			expect.stringMatching(/^o3co-oidf-/),
			"-f",
			join(suiteDir, "suite", "docker-compose-prebuilt.yml"),
			"-f",
			join(suiteDir, "override.yml"),
		]);
		expect(existsSync(suiteDir)).toBe(false);
	});

	it("holds every request to its API, while it starts and after, to the plan's deadline", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-api-"));
		const { command } = programs();
		const { docker } = dockers();
		const asked: { method: string; url: string; body?: unknown; signal?: AbortSignal }[] = [];
		const request = async (
			method: string,
			url: string,
			_ca: string,
			options: { body?: unknown; signal?: AbortSignal } = {},
		) => {
			asked.push({
				method,
				url,
				...(options.body === undefined ? {} : { body: options.body }),
				...(options.signal ? { signal: options.signal } : {}),
			});
			// The suite's answers: ready, then a plan made, then a test no longer running.
			if (url.includes("/api/plan?planName")) return { status: 201, body: { id: "p1" } };
			if (url.includes("wait-state")) return { status: 404, body: {} };
			return { status: 200, body: {} };
		};
		const deadline = new AbortController().signal;
		const suite = await startSuite(pin, join(dir, "suite"), host, join(dir, "suite.log"), tls, {
			command,
			docker,
			request,
			signal: deadline,
		});
		await suite.api("api/info/abc");
		// Any method, the status answered as it comes for the caller to judge.
		expect(await suite.call("POST", "api/plan?planName=p", { alias: "a" })).toEqual({
			status: 201,
			body: { id: "p1" },
		});
		expect((await suite.call("GET", "api/runner/m1/wait-state")).status).toBe(404);
		expect((await suite.call("DELETE", "api/runner/m1")).status).toBe(200);
		await suite.stop();
		expect(asked.map((a) => [a.method, a.url.replace(/^https:\/\/[^/]+/, "")])).toEqual([
			["GET", "/api/plan?length=1"],
			["GET", "/api/info/abc"],
			["POST", "/api/plan?planName=p"],
			["GET", "/api/runner/m1/wait-state"],
			["DELETE", "/api/runner/m1"],
		]);
		expect(asked[2]?.body).toEqual({ alias: "a" });
		for (const a of asked) expect(a.signal).toBe(deadline);
	});
});
