import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { frontRelayConfig, wireCertificates } from "@mod/front-relay/testing";
import { httpConfig } from "@mod/http/testing";
import { kernelConfig } from "@mod/kernel";
import { fakeKms, kmsServer } from "@mod/keys-kms/testing";
import { fakeRelay } from "@mod/mail-smtp/testing";
import { passkeyWitnessHttpConfig } from "@mod/passkey-witness-http/testing";
import { promiseNames } from "@mod/promises";
import { fakeRedis } from "@mod/redis/testing";
import { usersHttpConfig } from "@mod/users-http/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { patternNamed } from "../src/contract.ts";
import {
	asOperator,
	freePort,
	generated,
	generatedBy,
	listening,
	type Running,
	running,
	scripted,
} from "../src/testing.ts";
import { coreConfig, devConfig, registryOf } from "./configs.ts";

const bootMs = 20_000;
const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
let dir = "";
let certificates: Awaited<ReturnType<typeof wireCertificates>>;
let kms: Awaited<ReturnType<typeof kmsServer>>;
let redis: ReturnType<typeof fakeRedis>;
let redisPort = 0;
let relay: Awaited<ReturnType<typeof fakeRelay>>;
let registry: Record<string, unknown>;
let awsEnv: Record<string, string>;

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "create-app-fakes-"));
	certificates = await wireCertificates();
	const fake = fakeKms({
		[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
		[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
		[arn("sealing")]: { key: p256(), spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
	});
	kms = await kmsServer(fake.kms);
	const empty = join(dir, "empty");
	await writeFile(empty, "");
	// The child's environment is built whole (`running`): no AWS_ variable of the run reaches it.
	awsEnv = {
		AWS_ENDPOINT_URL_KMS: kms.url,
		AWS_ACCESS_KEY_ID: "AKIDTESTONLY",
		AWS_SECRET_ACCESS_KEY: "test-only",
		AWS_CONFIG_FILE: empty,
		AWS_SHARED_CREDENTIALS_FILE: empty,
		AWS_EC2_METADATA_DISABLED: "true",
	};
	redis = fakeRedis();
	// A server keeping every write, as the Core's durable spaces need.
	Object.assign(redis.settings, {
		appendonly: "yes",
		appendfsync: "always",
		"no-appendfsync-on-rewrite": "no",
	});
	redisPort = await redis.listen();
	relay = await fakeRelay();
	registry = await registryOf(dir);
}, 30_000);

afterAll(async () => {
	redis?.down();
	await kms?.close();
	await relay?.close();
	await certificates?.remove();
	await rm(dir, { recursive: true, force: true });
});

/** The Core's configuration over this file's fakes, the wire on `port`. */
const core = (port: number) =>
	coreConfig({ port, certificates, redis: redisPort, relay: relay.port, registry, arn });

/** Runs the app's entry until it listens on `port` or exits: true where it listened, then stopped with 0. */
async function bootsAndStops(run: Running, port: number) {
	expect(await listening(port, run, bootMs), run.out()).toBe(true);
	expect(await run.stop(), run.out()).toBe(0);
}

/** Runs the app's entry, which must refuse to boot (exit 78) naming `where`. */
async function refused(run: Running, where: RegExp) {
	expect(await run.exited, run.out()).toBe(78);
	expect(run.out()).toMatch(where);
}

describe("nextgen-core", () => {
	it(
		"boots as generated, on KMS, Redis, SMTP and a signed registry, configured as its files read it, and stops on SIGTERM",
		async () => {
			const app = await generated({ pattern: "nextgen-core" });
			const port = await freePort();
			// Each scalar through its variable, as .env.example names it; the rest in the local layer.
			const { env, local } = await asOperator(app.dir, core(port));
			expect(Object.keys(env).length).toBeGreaterThan(10);
			const run = await running(app.dir, "src/main.ts", local, { ...env, ...awsEnv });
			try {
				await bootsAndStops(run, port);
				// As generated, a login's request is taken pushed alone: the document it publishes says so.
				const published = join(app.dir, "published");
				const publish = await running(
					app.dir,
					"src/discovery-publish.ts",
					local,
					{ ...env, ...awsEnv },
					[published],
				);
				expect(await publish.exited, publish.out()).toBe(0);
				const document = JSON.parse(
					await readFile(join(published, ".well-known", "openid-configuration"), "utf8"),
				);
				expect(document).toMatchObject({
					require_pushed_authorization_requests: true,
					request_parameter_supported: false,
				});
			} finally {
				await run.stop();
				await app.remove();
			}
		},
		bootMs + 10_000,
	);

	it(
		"is refused at the promises it requires where http is changed to one process",
		async () => {
			const app = await generated({
				pattern: "nextgen-core",
				axes: { "@mod/http": "@mod/in-process" },
			});
			const port = await freePort();
			const { "core-wire": _, ...config } = core(port);
			const run = await running(app.dir, "src/main.ts", config, awsEnv);
			try {
				await refused(run, /promises\.required/);
			} finally {
				await run.stop();
				await app.remove();
			}
		},
		bootMs + 10_000,
	);

	it(
		"boots with client-credentials added, and is refused once the operator requires no-client-subject-token",
		async () => {
			const app = await generated({ pattern: "nextgen-core", add: ["@mod/client-credentials"] });
			try {
				const port = await freePort();
				const run = await running(app.dir, "src/main.ts", core(port), awsEnv);
				try {
					await bootsAndStops(run, port);
				} finally {
					await run.stop();
				}
				const required = [
					promiseNames.newAuthorization,
					promiseNames.clientToken,
					promiseNames.noClientSubjectToken,
				];
				const strict = await running(
					app.dir,
					"src/main.ts",
					{ ...core(port), promises: { required } },
					awsEnv,
				);
				try {
					await refused(strict, /promises\.required/);
				} finally {
					await strict.stop();
				}
			} finally {
				await app.remove();
			}
		},
		2 * bootMs + 10_000,
	);

	it(
		"boots with the outside ledger its card names, generated by the command as the card writes it",
		async () => {
			const card = patternNamed("nextgen-core")?.card ?? "";
			const written = /An outside ledger: `([^`]+)`/.exec(card)?.[1];
			expect(written, card).toBeDefined();
			const app = await generatedBy(["--pattern", "nextgen-core", ...(written ?? "").split(" ")]);
			try {
				const port = await freePort();
				// The outside ledger's place: no call goes to it at boot.
				const { "users-local": _local, ...base } = core(port);
				const config = {
					...base,
					...usersHttpConfig(),
					...passkeyWitnessHttpConfig(),
					// Both builders' ledger, at one origin.
					outbound: { allow: [...base.outbound.allow, "ledger.example.invalid"] },
				};
				const run = await running(app.dir, "src/main.ts", config, awsEnv);
				try {
					await bootsAndStops(run, port);
				} finally {
					await run.stop();
				}
			} finally {
				await app.remove();
			}
		},
		bootMs + 10_000,
	);

	it(
		"boots with sign-up added",
		async () => {
			const app = await generated({ pattern: "nextgen-core", add: ["@mod/sign-up"] });
			const port = await freePort();
			const run = await running(app.dir, "src/main.ts", core(port), awsEnv);
			try {
				await bootsAndStops(run, port);
			} finally {
				await run.stop();
				await app.remove();
			}
		},
		bootMs + 10_000,
	);

	it(
		"is refused, as generated, where the operator registers a client by a shared secret",
		async () => {
			const app = await generated({ pattern: "nextgen-core" });
			const port = await freePort();
			const config = { ...core(port), ...clientsConfig([confidentialClient({ id: "rp-secret" })]) };
			const run = await running(app.dir, "src/main.ts", config, awsEnv);
			try {
				await refused(run, new RegExp(`promises\\.required\\.\\d: ${promiseNames.clientToken}`));
			} finally {
				await run.stop();
				await app.remove();
			}
		},
		bootMs + 10_000,
	);
});

describe("nextgen-front", () => {
	it(
		"boots as generated, reaching no Core until a request comes",
		async () => {
			const app = await generated({ pattern: "nextgen-front" });
			const port = await freePort();
			const config = {
				...kernelConfig(),
				...httpConfig({ port, "public-origin": "https://login.example.invalid" }),
				...frontRelayConfig(certificates, { "core-port": await freePort() }),
			};
			const run = await running(app.dir, "src/main.ts", config);
			try {
				await bootsAndStops(run, port);
			} finally {
				await run.stop();
				await app.remove();
			}
		},
		bootMs + 10_000,
	);
});

describe("nextgen-dev", () => {
	it(
		"boots in one process, is refused where a promise it cannot hold is required, and serves what it publishes",
		async () => {
			const app = await generated({ pattern: "nextgen-dev" });
			const port = await freePort();
			const issuerPort = await freePort();
			const issuer = `http://127.0.0.1:${issuerPort}/tenant`;
			const config = devConfig({ port, relay: relay.port, registry, issuer });
			try {
				const run = await running(app.dir, "src/main.ts", config);
				try {
					await bootsAndStops(run, port);
				} finally {
					await run.stop();
				}
				const strict = { ...config, promises: { required: [promiseNames.newAuthorization] } };
				const refusedRun = await running(app.dir, "src/main.ts", strict);
				try {
					await refused(refusedRun, /promises\.required/);
				} finally {
					await refusedRun.stop();
				}
				const published = join(app.dir, "published");
				await mkdir(join(published, "tenant"), { recursive: true });
				for (const [file, at] of [
					["src/discovery-publish.ts", published],
					["src/keys-publish.ts", join(published, "tenant")],
				] as const) {
					const entry = await running(app.dir, file, config, {}, [at]);
					expect(await entry.exited, entry.out()).toBe(0);
				}
				const reader = `http://127.0.0.1:${port}`;
				const serve = await running(
					app.dir,
					"node_modules/@mod/publish-serve/src/main.ts",
					config,
					{},
					[published, `http://127.0.0.1:${issuerPort}`, reader],
				);
				try {
					expect(await listening(issuerPort, serve, bootMs), serve.out()).toBe(true);
					const answer = await fetch(`${issuer}/.well-known/openid-configuration`);
					const document = (await answer.json()) as {
						readonly issuer: string;
						readonly jwks_uri: string;
					};
					expect(document.issuer).toBe(issuer);
					// The operator's own configuration turned pushed-only off: the document says so.
					expect(document).toMatchObject({
						require_pushed_authorization_requests: false,
						request_parameter_supported: true,
					});
					const rfc8414 = await fetch(
						`http://127.0.0.1:${issuerPort}/.well-known/oauth-authorization-server/tenant`,
					);
					expect(rfc8414.status).toBe(200);
					const keys = await fetch(document.jwks_uri, { headers: { origin: reader } });
					expect(keys.status).toBe(200);
					expect(keys.headers.get("access-control-allow-origin")).toBe(reader);
					expect(((await keys.json()) as { readonly keys: unknown[] }).keys.length).toBeGreaterThan(
						0,
					);
				} finally {
					await serve.stop();
				}
			} finally {
				await app.remove();
			}
		},
		4 * bootMs + 10_000,
	);
});

describe("each pattern started as generated, held by Node's permission model", () => {
	/** Each pattern's configuration and environment, as its own boot test above gives them. */
	const configured = async (pattern: string, dir: string, port: number) => {
		if (pattern === "nextgen-dev") {
			const issuer = `http://127.0.0.1:${await freePort()}/tenant`;
			return { config: devConfig({ port, relay: relay.port, registry, issuer }), env: {} };
		}
		if (pattern === "nextgen-front") {
			const config = {
				...kernelConfig(),
				...httpConfig({ port, "public-origin": "https://login.example.invalid" }),
				...frontRelayConfig(certificates, { "core-port": await freePort() }),
			};
			return { config, env: {} };
		}
		const { env, local } = await asOperator(dir, core(port));
		return { config: local, env: { ...env, ...awsEnv } };
	};
	/** The permission model's events a run wrote, each a JSON line on standard error. */
	const events = (out: string) =>
		out.split("\n").filter((line) => line.includes('"app-permissions.event"'));

	for (const pattern of ["nextgen-core", "nextgen-front", "nextgen-dev"]) {
		it(
			`${pattern}: audited, boots with no read, process or network beyond its grants; enforced, boots and stops`,
			async () => {
				const app = await generated({ pattern });
				try {
					const port = await freePort();
					const { config, env } = await configured(pattern, app.dir, port);
					for (const mode of ["audit", "enforce"]) {
						const run = await scripted(app.dir, "start", config, { ...env, APP_PERMISSION: mode });
						expect(await listening(port, run, bootMs), run.out()).toBe(true);
						expect(await run.stop(), run.out()).toBe(0);
						expect(events(run.out()), mode).toEqual([]);
						// The entry that ran was held so: the preload says how as it loads.
						expect(run.out()).toContain(`{"event":"app-permissions.held","mode":"${mode}"}`);
					}
					// What the start grants, for this configuration, under enforce: no write, and no process but where a package's forks start one.
					const printed = await scripted(
						app.dir,
						"start",
						config,
						{ ...env, APP_PERMISSION: "enforce" },
						["--print"],
					);
					expect(await printed.exited, printed.out()).toBe(0);
					const argv = JSON.parse(printed.out().trim().split("\n").at(-1) ?? "[]") as string[];
					expect(argv).toContain("--permission");
					// And unset, audited, until every path an app runs shows no event under it.
					const byDefault = await scripted(app.dir, "start", config, env, ["--print"]);
					expect(await byDefault.exited, byDefault.out()).toBe(0);
					expect(byDefault.out()).toContain("--permission-audit");
					expect(argv).toEqual(
						expect.arrayContaining([
							"--disable-proto=throw",
							"--disallow-code-generation-from-strings",
						]),
					);
					expect(argv.some((flag) => flag.startsWith("--allow-fs-write"))).toBe(false);
					// The resolver resolves in the process by default: the Core starts no child process.
					expect(argv).not.toContain("--allow-child-process");
				} finally {
					await app.remove();
				}
			},
			3 * bootMs + 10_000,
		);
	}
});
