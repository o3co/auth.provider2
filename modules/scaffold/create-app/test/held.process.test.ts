import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { frontRelayConfig, wireCertificates } from "@mod/front-relay/testing";
import { httpConfig } from "@mod/http/testing";
import { kernelConfig } from "@mod/kernel";
import { fakeRelay } from "@mod/mail-smtp/testing";
import { promiseNames } from "@mod/promises";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { freePort, generated, listening, type Running, scripted } from "../src/testing.ts";
import { devConfig, registryOf } from "./configs.ts";

// The flip's evidence beyond boot, for the legs a generated app runs without an outside system
// (permission-model-plan.md, "The flip's evidence: plan", E1): each run through the manifest's
// `start`, under audit (the held line, no event line, and what the leg does) and under enforce (the
// same answer). Network is held only where Node takes --allow-net, so a zero says nothing of the
// network on Node 24; these legs reach none. prom-client tries /proc/self/limits at registration
// everywhere, and reads /proc/self/fd and /proc/self/status at a scrape on Linux alone: locally the
// scrape shows its route and the limits grant, on the Linux runners its /proc reads as well.

const bootMs = 20_000;
let dir = "";
let relay: Awaited<ReturnType<typeof fakeRelay>>;
let registry: Record<string, unknown>;
let certificates: Awaited<ReturnType<typeof wireCertificates>>;

beforeAll(async () => {
	// Real paths: a grant is checked by the path as named, and /var is a link on macOS.
	dir = await realpath(await mkdtemp(join(tmpdir(), "create-app-held-")));
	relay = await fakeRelay();
	registry = await registryOf(dir);
	certificates = await wireCertificates();
}, 30_000);

afterAll(async () => {
	await relay?.close();
	await certificates?.remove();
	await rm(dir, { recursive: true, force: true });
});

/** The permission model's event lines a run wrote: anywhere in its output, so none is missed. */
const events = (out: string) =>
	out.split("\n").filter((line) => line.includes('"event":"app-permissions.event"'));
const held = (mode: string) => `{"event":"app-permissions.held","mode":"${mode}"}`;

/** Runs `start` held in `mode` until it listens on `port`, calls `use`, then stops it with 0: its output. */
async function heldWhile(
	appDir: string,
	config: unknown,
	mode: "audit" | "enforce",
	port: number,
	use: (run: Running) => Promise<void>,
) {
	const run = await scripted(appDir, "start", config, { APP_PERMISSION: mode });
	let listened = false;
	try {
		listened = await listening(port, run, bootMs);
		expect(listened, run.out()).toBe(true);
		await use(run);
	} finally {
		// Its own exit code once it served; where it never listened, the reason above stands.
		const code = await run.stop();
		if (listened) expect(code, run.out()).toBe(0);
	}
	expect(run.out()).toContain(held(mode));
	expect(events(run.out()), mode).toEqual([]);
	return run.out();
}

/**
 * A scrape of `path` on the app's port: 200, Prometheus' text, the process's CPU counted; on Linux the
 * metrics its /proc reads make too (open and most file descriptors, resident memory), so a grant they
 * need is shown used, not only unrefused.
 */
async function scraped(port: number, path = "/metrics") {
	const answer = await fetch(`http://127.0.0.1:${port}${path}`);
	expect(answer.status).toBe(200);
	const text = await answer.text();
	expect(text).toContain("auth_provider_process_cpu_user_seconds_total");
	if (process.platform !== "linux") return;
	// Gauges start at 0, so a read is shown by a value above it: the open descriptors and the
	// resident memory /proc/self/fd and /proc/self/status give. The limit's is a number or Nan.
	const value = (name: string) =>
		Number(new RegExp(`^auth_provider_process_${name} (\\S+)$`, "m").exec(text)?.[1]);
	for (const name of ["open_fds", "resident_memory_bytes"])
		expect(value(name), name).toBeGreaterThan(0);
	expect(text).toMatch(/^auth_provider_process_max_fds /m);
}

const pem = () =>
	generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	}) as string;

/** The dev pattern's configuration on `port`, its keys as given. */
async function dev(port: number, keys?: readonly Record<string, string>[]) {
	const issuer = `http://127.0.0.1:${await freePort()}/tenant`;
	const config = devConfig({ port, relay: relay.port, registry, issuer });
	return keys === undefined ? config : { ...config, "keys-local": { keys } };
}

describe("a generated app held beyond its boot (the flip's evidence, E1)", () => {
	it(
		"nextgen-dev: keys-local's keys from a file and inline, read at its boot; a scrape; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				// The Core's key from a file the configuration names; the others inline (mixed members).
				const file = join(dir, "core-test.pem");
				await writeFile(file, pem());
				const keys = [
					{ kid: "test", pem: pem() },
					{ kid: "core-test", file },
					{ kid: "seal-test", pem: pem() },
				];
				const config = await dev(port, keys);
				// keys-local reads every key at boot, refusing one it cannot, so listening shows the file key
				// read; a key in memory signs with no access the model holds.
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-front: a scrape; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-front" });
			try {
				const port = await freePort();
				const config = {
					...kernelConfig(),
					...httpConfig({ port, "public-origin": "https://login.example.invalid" }),
					...frontRelayConfig(certificates, { "core-port": await freePort() }),
				};
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-dev: an application.conf including a file outside the app, which includes a nested one and probes a missing optional one; no event under audit, the same under enforce",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				const outside = join(dir, "outside");
				await mkdir(outside, { recursive: true });
				// Outside the app, which grants its own directory whole: the included file, the missing
				// optional one it probes, and the nested one it includes, which moves the scrape's path, so
				// answering there shows each read (or probed) held.
				await writeFile(join(outside, "far.conf"), 'include "absent"\ninclude "deeper"\n');
				await writeFile(
					join(outside, "deeper.conf"),
					'metrics-prometheus { path = "/far-metrics" }\n',
				);
				const conf = join(app.dir, "config", "application.conf");
				await writeFile(
					conf,
					`${await readFile(conf, "utf8")}\ninclude file("${join(outside, "far.conf")}")\n`,
				);
				const config = await dev(port);
				for (const mode of ["audit", "enforce"] as const)
					await heldWhile(app.dir, config, mode, port, () => scraped(port, "/far-metrics"));
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"nextgen-dev: refused at its boot under enforce: 78 and its own refused lines, held, and no event line",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			try {
				const port = await freePort();
				const strict = {
					...(await dev(port)),
					promises: { required: [promiseNames.newAuthorization] },
				};
				const run = await scripted(app.dir, "start", strict, { APP_PERMISSION: "enforce" });
				try {
					// Where it wrongly boots, it listens: told at once, not at the test's limit.
					const ended = await Promise.race([
						run.exited,
						listening(port, run, bootMs).then((up) => (up ? "up" : "neither exited nor listened")),
					]);
					expect(ended, run.out()).toBe(78);
					expect(run.out()).toMatch(/refused promises\.required/);
					expect(run.out()).toContain(held("enforce"));
					expect(events(run.out())).toEqual([]);
				} finally {
					await run.stop();
				}
			} finally {
				await app.remove();
			}
		},
		bootMs + 10_000,
	);
});
