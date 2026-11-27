import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { type Mode, nodeSettings, type Permissions } from "@mod/app-permissions";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fakeKms, kmsServer } from "../src/testing.ts";

// keys-kms held by Node's permission model under `enforce`, granted what its manifest's
// `permissions` declare and nothing else (the plan's AWS providers: what the SDK's default chain
// takes under enforce, and what it must not; one known gap pinned as it is). Each run is a process
// of its own (test/held/child.ts) with the flags app-permissions makes, an environment built whole
// (no AWS_ variable of the run's), and every call on loopback: KMS's wire fake, an STS fake for web
// identity, and a container credentials fake standing for another identity the chain could fall
// back to unsaid.

const root = fileURLToPath(new URL("../../../../", import.meta.url));
const child = fileURLToPath(new URL("./held/child.ts", import.meta.url));
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const permissions = manifest.permissions as Permissions;
const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const fake = fakeKms({
	[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
	[arn("sealing")]: { key: p256(), spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
});
const section = {
	region: "eu-west-1",
	keys: [
		{ kid: "test", "key-id": arn("authority") },
		{ kid: "core-test", "key-id": arn("core") },
		{ kid: "seal-test", "key-id": arn("sealing") },
	],
};
const runMs = 20_000;

let dir = "";
let home = "";
let kms: Awaited<ReturnType<typeof kmsServer>>;
let sts: Awaited<ReturnType<typeof listened>> & { tokens: string[] };
let container: Awaited<ReturnType<typeof listened>> & { asked: number };

/** A server on loopback answering each request's body by `answer`: its URL and its end. */
async function listened(answer: (request: IncomingMessage, body: string) => [string, string]) {
	const server: Server = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			const [type, text] = answer(request, body);
			response.writeHead(200, { "content-type": type }).end(text);
		});
	});
	const port = await new Promise<number>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
	});
	return {
		url: `http://127.0.0.1:${port}`,
		close: () =>
			new Promise<void>((done) => {
				server.closeAllConnections();
				server.close(() => done());
			}),
	};
}

/**
 * Credentials for a minute: inside the SDK's refresh window (credential-provider-node's
 * `memoizeChain`, five minutes, as @smithy/core's `EXPIRATION_MS` too), so a call starts a refresh,
 * with no wait for an expiry. Should the SDK narrow its
 * window below a minute, the refresh case fails: the file is then read once, and the second token's
 * identity never signs.
 */
const soon = () => new Date(Date.now() + 60_000).toISOString();

beforeAll(async () => {
	// Real paths: a grant is checked by the path as named, and /var is a link on macOS.
	dir = await realpath(await mkdtemp(join(tmpdir(), "keys-kms-enforce-")));
	home = join(dir, "home");
	kms = await kmsServer(fake.kms);
	const tokens: string[] = [];
	// STS's AssumeRoleWithWebIdentity (Query, XML): an identity named after the token it was given.
	const stsServer = await listened((_, body) => {
		const token = new URLSearchParams(body).get("WebIdentityToken") ?? "";
		tokens.push(token);
		const xml = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AKIDWEB${token.toUpperCase()}</AccessKeyId><SecretAccessKey>test-only</SecretAccessKey><SessionToken>test-only</SessionToken><Expiration>${soon()}</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/core/held</Arn><AssumedRoleId>AROATESTONLY:held</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`;
		return ["text/xml", xml];
	});
	sts = Object.assign(stsServer, { tokens });
	const containerServer = await listened(() => {
		container.asked += 1;
		const credentials = {
			AccessKeyId: "AKIDFALLBACK",
			SecretAccessKey: "test-only",
			Token: "test-only",
			Expiration: soon(),
		};
		return ["application/json", JSON.stringify(credentials)];
	});
	container = Object.assign(containerServer, { asked: 0 });
}, 30_000);

afterAll(async () => {
	await kms?.close();
	await sts?.close();
	await container?.close();
	await rm(dir, { recursive: true, force: true });
});

/**
 * The child run held in `mode`, its environment `env` and the test's endpoints alone, granted what
 * keys-kms declares: its JSON lines, and `more` a way to ask it to sign again, resolving once it told
 * the next line. `use` runs while it runs; it is ended after.
 */
async function held(
	mode: Mode,
	env: Record<string, string>,
	use: (run: {
		lines: unknown[];
		again: (ms?: number) => Promise<void>;
	}) => Promise<void> = async () => {},
) {
	const whole = {
		PATH: process.env.PATH ?? "",
		HOME: home,
		AWS_REGION: "eu-west-1",
		AWS_ENDPOINT_URL_KMS: kms.url,
		AWS_ENDPOINT_URL_STS: sts.url,
		AWS_EC2_METADATA_DISABLED: "true",
		AWS_CONFIG_FILE: join(dir, "absent-config"),
		AWS_SHARED_CREDENTIALS_FILE: join(dir, "absent-credentials"),
		...env,
	};
	const settings = nodeSettings(
		{
			code: [root],
			declared: [{ package: manifest.name, section: "keys-kms", forks: false, permissions }],
			network: true,
		},
		{
			mode,
			tree: { "keys-kms": section },
			reads: { read: [], probed: [] },
			env: whole,
			home,
			cwd: dir,
			appRoot: root,
			allowsNet: process.allowedNodeEnvironmentFlags.has("--allow-net"),
		},
	);
	if (!("argv" in settings)) throw new Error(`no grant: ${JSON.stringify(settings)}`);
	const run = spawn(process.execPath, [...settings.argv, child, JSON.stringify(section)], {
		cwd: dir,
		env: whole,
		stdio: ["pipe", "pipe", "pipe"],
	});
	let stderr = "";
	run.stderr.on("data", (chunk) => {
		stderr += chunk;
	});
	const lines: unknown[] = [];
	const waiters: { told: () => void; ended: (why: string) => void }[] = [];
	createInterface({ input: run.stdout }).on("line", (line) => {
		lines.push(JSON.parse(line));
		waiters.shift()?.told();
	});
	// A child that ended tells no more lines: a wait for one ends at once, showing what it told.
	let ended = false;
	const exited = new Promise<number | null>((done) =>
		run.on("close", (code) => {
			ended = true;
			for (const waiter of waiters.splice(0)) waiter.ended(`ended (${code})`);
			done(code);
		}),
	);
	const next = (ms = runMs) =>
		new Promise<void>((resolve, reject) => {
			const fail = (why: string) =>
				reject(new Error(`no line: ${why}\n${JSON.stringify(lines)}\n${stderr}`));
			if (ended) return fail("ended");
			const timer = setTimeout(() => fail("not in time"), ms);
			waiters.push({
				told: () => {
					clearTimeout(timer);
					resolve();
				},
				ended: (why) => {
					clearTimeout(timer);
					fail(why);
				},
			});
		});
	try {
		await next();
		await use({
			lines,
			again: async (ms?: number) => {
				const told = next(ms);
				run.stdin.write("\n");
				await told;
			},
		});
	} finally {
		run.stdin.end();
		const timer = setTimeout(() => run.kill("SIGKILL"), runMs);
		await exited;
		clearTimeout(timer);
	}
	return { lines, stderr };
}

describe("keys-kms held by Node's permission model under enforce, granted what it declares", () => {
	it(
		"refuses where a profile's own web_identity_token_file is not granted, never falling back to another identity; unheld, the same profile signs",
		async () => {
			const token = join(dir, "profile-token");
			await writeFile(token, "profile");
			const config = join(dir, "profile-config");
			await writeFile(
				config,
				`[profile chosen]\nrole_arn = arn:aws:iam::111122223333:role/core\nweb_identity_token_file = ${token}\n`,
			);
			const env = {
				AWS_CONFIG_FILE: config,
				AWS_PROFILE: "chosen",
				// Another identity the chain could reach: a container's credentials on loopback.
				AWS_CONTAINER_CREDENTIALS_FULL_URI: `${container.url}/credentials`,
			};
			const before = kms.callers.length;
			const refused = await held("enforce", env);
			// The boot is refused at each key by the model's refusal (its code and kind, the error's own
			// fields), the read it kept named: the profile's token file. No call reached KMS under any
			// identity, and the container's was never asked.
			expect(refused.lines, refused.stderr).toEqual([
				{
					failed: expect.objectContaining({
						name: "BootRefused",
						refusals: section.keys.map((_, at) => ({
							where: `keys-kms.keys.${at}.key-id`,
							reason:
								"an access for the call is outside what the Core is granted (ERR_ACCESS_DENIED, FileSystemRead)",
						})),
					}),
				},
				{
					logged: [
						{
							level: "warn",
							event: "keys-kms.credentials_refused",
							fields: { permission: "FileSystemRead", resource: token },
						},
					],
				},
			]);
			expect(kms.callers.slice(before)).toEqual([]);
			expect(container.asked).toBe(0);
			// The control: unheld, the profile's token is read and its identity signs.
			const tokens = sts.tokens.length;
			const off = await held("off", env);
			expect(off.lines, off.stderr).toEqual([{ signed: 1 }, { logged: [] }]);
			expect(sts.tokens.slice(tokens)).toContain("profile");
			expect(kms.callers.at(-1)).toBe("AKIDWEBPROFILE");
		},
		3 * runMs,
	);

	// The known gap, before the flip: under enforce the SDK turns the model's refusal of the exec into
	// "try the next provider", so another identity signs. To be refused at boot by keys-kms itself.
	it(
		"KNOWN GAP: a profile's credential_process is skipped under enforce, and the chain signs as the next identity, unsaid; unheld, the process's identity signs",
		async () => {
			const config = join(dir, "process-config");
			const answer = '{"Version":1,"AccessKeyId":"AKIDPROCESS","SecretAccessKey":"test-only"}';
			await writeFile(config, `[profile chosen]\ncredential_process = printf '${answer}'\n`);
			const env = {
				AWS_CONFIG_FILE: config,
				AWS_PROFILE: "chosen",
				AWS_CONTAINER_CREDENTIALS_FULL_URI: `${container.url}/credentials`,
			};
			const off = await held("off", env);
			expect(off.lines, off.stderr).toEqual([{ signed: 1 }, { logged: [] }]);
			expect(kms.callers.at(-1)).toBe("AKIDPROCESS");
			const asked = container.asked;
			const enforced = await held("enforce", env);
			expect(enforced.lines, enforced.stderr).toEqual([{ signed: 1 }, { logged: [] }]);
			expect(kms.callers.at(-1)).toBe("AKIDFALLBACK");
			expect(container.asked).toBeGreaterThan(asked);
		},
		2 * runMs,
	);

	it(
		"reads AWS_WEB_IDENTITY_TOKEN_FILE again at each refresh, the token rewritten after the first sign, and signs as the new identity",
		async () => {
			const token = join(dir, "web-token");
			await writeFile(token, "first");
			const env = {
				AWS_WEB_IDENTITY_TOKEN_FILE: token,
				AWS_ROLE_ARN: "arn:aws:iam::111122223333:role/core",
				AWS_ROLE_SESSION_NAME: "held",
			};
			const tokens = sts.tokens.length;
			const callers = kms.callers.length;
			/**
			 * Signs again until the second token's identity signs or `ms` pass, each sign waited for no
			 * longer than what is left: how many signs it took.
			 */
			const signsUntilSecond = async (again: (ms?: number) => Promise<void>, ms: number) => {
				const end = Date.now() + ms;
				for (let at = 1; Date.now() < end; at += 1) {
					await again(Math.max(1, end - Date.now()));
					if (kms.callers.at(-1) === "AKIDWEBSECOND") return at;
					await new Promise((resolve) => setTimeout(resolve, 100));
				}
				return undefined;
			};
			let took: number | undefined;
			const run = await held("enforce", env, async ({ again }) => {
				await writeFile(token, "second");
				// Within the refresh window, a call starts a refresh that reads the file again, and the
				// SDK signs with the identity it holds meanwhile: the second token's identity signs once a
				// refresh begun after the rewrite has ended, a few calls on at most.
				// Ten seconds of the case's forty: its boot before and the child's end after keep the rest.
				took = await signsUntilSecond(again, 10_000);
			});
			expect(
				took,
				JSON.stringify({ lines: run.lines, asked: sts.tokens.slice(tokens) }),
			).toBeDefined();
			expect(run.lines.at(-1), run.stderr).toEqual({ logged: [] });
			expect(run.lines.slice(0, -1)).toEqual(
				Array.from({ length: (took ?? 0) + 1 }, (_, at) => ({ signed: at + 1 })),
			);
			// The file read again at the refreshes: the first token until the rewrite, then the second
			// alone, the first never asked again.
			const asked = sts.tokens.slice(tokens);
			expect(asked[0]).toBe("first");
			const second = asked.indexOf("second");
			expect(second).toBeGreaterThan(0);
			expect(
				asked.slice(second).every((t) => t === "second"),
				JSON.stringify(asked),
			).toBe(true);
			expect(kms.callers.slice(callers).at(-1)).toBe("AKIDWEBSECOND");
		},
		2 * runMs,
	);

	it(
		"signs as the profile AWS_PROFILE selects in the shared credentials file, not its default",
		async () => {
			const credentials = join(dir, "credentials");
			await writeFile(
				credentials,
				"[default]\naws_access_key_id = AKIDDEFAULT\naws_secret_access_key = test-only\n\n[chosen]\naws_access_key_id = AKIDCHOSEN\naws_secret_access_key = test-only\n",
			);
			const run = await held("enforce", {
				AWS_SHARED_CREDENTIALS_FILE: credentials,
				AWS_PROFILE: "chosen",
			});
			expect(run.lines, run.stderr).toEqual([{ signed: 1 }, { logged: [] }]);
			expect(kms.callers.at(-1)).toBe("AKIDCHOSEN");
			expect(kms.callers).not.toContain("AKIDDEFAULT");
		},
		2 * runMs,
	);
});
