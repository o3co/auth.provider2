/**
 * The held process tests' shared part: the fakes of the generated apps' outside systems (KMS's wire
 * fake, the relay, the registry, the wire's certificates), runs held through the manifest's `start`,
 * and a generated Core behind a generated Front. Two files use it, each typed by one configuration:
 * `held.process.test.ts` by the root's, and `held-mail.process.test.ts`, which reads the login
 * screen's SDK, by `tsconfig.sdk-tests.json` (with the DOM's types), as Node's and the DOM's
 * `CryptoKey` types collide in x509-path's testing helpers that the first reads.
 */
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { frontRelayConfig, wireCertificates } from "@mod/front-relay/testing";
import { httpConfig } from "@mod/http/testing";
import { kernelConfig } from "@mod/kernel";
import { fakeKms, kmsServer } from "@mod/keys-kms/testing";
import { fakeRelay } from "@mod/mail-smtp/testing";
import { afterAll, beforeAll, expect } from "vitest";
import {
	asOperator,
	freePort,
	generated,
	listening,
	type Running,
	scripted,
} from "../src/testing.ts";
import { coreConfig, registryOf } from "./configs.ts";

export const bootMs = 20_000;
export let dir = "";
export let relay: Awaited<ReturnType<typeof fakeRelay>>;
export let registry: Record<string, unknown>;
export let certificates: Awaited<ReturnType<typeof wireCertificates>>;
let kms: Awaited<ReturnType<typeof kmsServer>>;
export let awsEnv: Record<string, string>;
/** The Core's sealing key, as KMS holds it: the screen seals a first key's start to it. */
export let sealing: KeyObject;
export const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;
export const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;

/** Starts the outside systems' fakes before a file's held tests and stops them after: each file calls it once. */
export function heldFixtures() {
	beforeAll(async () => {
		// Real paths: a grant is checked by the path as named, and /var is a link on macOS.
		dir = await realpath(await mkdtemp(join(tmpdir(), "create-app-held-")));
		relay = await fakeRelay();
		registry = await registryOf(dir);
		certificates = await wireCertificates();
		sealing = p256();
		// The Core's outside system as boot.process.test.ts has it: KMS's wire fake.
		const fake = fakeKms({
			[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
			[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
			[arn("sealing")]: { key: sealing, spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
		});
		kms = await kmsServer(fake.kms);
		const empty = join(dir, "empty");
		await writeFile(empty, "");
		// The child's environment is built whole: no AWS_ variable of the run reaches it.
		awsEnv = {
			AWS_ENDPOINT_URL_KMS: kms.url,
			AWS_ACCESS_KEY_ID: "AKIDTESTONLY",
			AWS_SECRET_ACCESS_KEY: "test-only",
			AWS_CONFIG_FILE: empty,
			AWS_SHARED_CREDENTIALS_FILE: empty,
			AWS_EC2_METADATA_DISABLED: "true",
		};
	}, 30_000);

	afterAll(async () => {
		await kms?.close();
		await relay?.close();
		await certificates?.remove();
		await rm(dir, { recursive: true, force: true });
	});
}

/** The permission model's event lines a run wrote: anywhere in its output, so none is missed. */
export const events = (out: string) =>
	out.split("\n").filter((line) => line.includes('"event":"app-permissions.event"'));
export const held = (mode: string) => `{"event":"app-permissions.held","mode":"${mode}"}`;

/** Runs `start` held in `mode` until it listens on `port`, calls `use`, then stops it with 0: its output. */
export async function heldWhile(
	appDir: string,
	config: unknown,
	mode: "audit" | "enforce",
	port: number,
	use: (run: Running) => Promise<void>,
	env: Record<string, string> = {},
	told: "none" | "some" = "none",
) {
	const run = await scripted(appDir, "start", config, { ...env, APP_PERMISSION: mode });
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
	// A refusal publishes its event too, under enforce: none told is what shows none was refused.
	if (told === "none") expect(events(run.out()), mode).toEqual([]);
	return run.out();
}

/** Polls `holds` every 100 ms until it is true or `ms` pass: whether it came true. */
export async function until(holds: () => boolean, ms = 10_000) {
	for (const end = Date.now() + ms; Date.now() < end; ) {
		if (holds()) return true;
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
	return holds();
}

/**
 * The Core held in `mode` behind a generated Front held the same way, `drive` sent through the Front
 * at its port; `config` the Core's. The Core's run ends stopped once `after` holds of its output;
 * answers the Core's output. `told` is the Core's: `some` for a run whose grant a test withholds, to
 * see the model tell what it would refuse.
 */
export async function throughFront(
	core: { dir: string },
	front: { dir: string },
	config: Record<string, unknown>,
	mode: "audit" | "enforce",
	drive: (frontPort: number, coreRun: Running) => Promise<void>,
	after: (out: string) => boolean,
	extraEnv: Record<string, string> = {},
	told: "none" | "some" = "none",
) {
	const corePort = (config.http as { port: number }).port;
	const { env, local } = await asOperator(core.dir, config);
	const frontPort = await freePort();
	// The test reaches the Front from loopback, its trusted proxy, naming one sender for every
	// request (RFC 5737's documentation range), as the OIDF scene's edge does.
	const frontConfig = {
		...kernelConfig(),
		...httpConfig({
			port: frontPort,
			"public-origin": "https://login.example.invalid",
			"trusted-proxies": ["127.0.0.1"],
		}),
		...frontRelayConfig(certificates, { "core-port": corePort }),
	};
	return heldWhile(
		core.dir,
		local,
		mode,
		corePort,
		async (coreRun) => {
			// The Front held the same way: its relay over the wire is held too.
			await heldWhile(front.dir, frontConfig, mode, frontPort, async () => {
				await drive(frontPort, coreRun);
				expect(await until(() => after(coreRun.out())), coreRun.out()).toBe(true);
			});
		},
		{ ...env, ...awsEnv, ...extraEnv },
		told,
	);
}

/** A POST through the Front from the sender every request names, its deadline a boot's. */
export const sentThrough = (
	frontPort: number,
	path: string,
	init: { type: string; body: string },
) =>
	fetch(`http://127.0.0.1:${frontPort}${path}`, {
		method: "POST",
		headers: { "content-type": init.type, "x-forwarded-for": "192.0.2.10" },
		body: init.body,
		signal: AbortSignal.timeout(bootMs),
	});

/** `throughFront` with an unknown client's token request, which the Core refuses and audits. */
export const auditedThroughFront = (
	core: { dir: string },
	front: { dir: string },
	config: Record<string, unknown>,
	mode: "audit" | "enforce",
	after: (out: string) => boolean,
	extraEnv: Record<string, string> = {},
	told: "none" | "some" = "none",
) =>
	throughFront(
		core,
		front,
		config,
		mode,
		async (frontPort, coreRun) => {
			const answer = await sentThrough(frontPort, "/oauth/token", {
				type: "application/x-www-form-urlencoded",
				body: new URLSearchParams({
					grant_type: "client_credentials",
					client_id: "nobody-registered",
					client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
					client_assertion: "a.b.c",
				}).toString(),
			});
			expect(answer.status, coreRun.out()).toBe(401);
		},
		after,
		extraEnv,
		told,
	);

/** The Core on the memory store, as the OIDF scene runs it, `config` over it. */
export const memoryCore = (port: number, config: Record<string, unknown> = {}) => {
	const { redis: _redis, ...base } = coreConfig({
		port,
		certificates,
		redis: 1,
		relay: relay.port,
		registry,
		arn,
	});
	return {
		...base,
		store: { "accept-volatile": true, "accept-unauthenticated": true },
		...config,
	};
};

/** A generated Core on the memory store (`beside` naming more of its plan) and a generated Front, removed after `use` whatever it does. */
export async function coreAndFront(
	use: (apps: { core: { dir: string }; front: { dir: string } }) => Promise<void>,
	beside: { axes?: Record<string, string>; add?: string[] } = {},
) {
	const made: { dir: string; remove: () => Promise<void> }[] = [];
	try {
		const core = await generated({
			pattern: "nextgen-core",
			axes: { "@mod/store": "@mod/store", ...beside.axes },
			add: beside.add ?? [],
		});
		made.push(core);
		const front = await generated({ pattern: "nextgen-front" });
		made.push(front);
		await use({ core, front });
	} finally {
		await Promise.all(made.map((app) => app.remove()));
	}
}
