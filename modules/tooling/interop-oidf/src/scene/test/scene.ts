/**
 * The provider as the OIDF run meets it: the generated `nextgen-core` and `nextgen-front`, each run
 * as its operator runs it in a process of its own, over fakes of the outside systems the Core
 * reaches (KMS, SMTP, the signed registry) and the memory store on the store axis (redis's fake
 * boots the module and no more); and an https front at the issuer's origin, the deployment's edge, answering what the
 * operator publishes (the Core app's own entries wrote it) as the publisher would, and passing
 * everything else to the Front. The publisher is the operator's and trusted; the harness plays it.
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditConfig } from "@mod/audit/testing";
import { auditHttpConfig } from "@mod/audit-http/testing";
import { authorizeConfig } from "@mod/authorize/testing";
import { publisherKey, signedBy } from "@mod/clients-registry/testing";
import { type Front, type FrontRequest, selfSigned, startFront } from "@mod/conformance-front";
import { coreWireConfig } from "@mod/core-wire/testing";
import {
	asOperator,
	freePort,
	generated,
	listening,
	type Running,
	running,
} from "@mod/create-app/testing";
import { dpopConfig } from "@mod/dpop/testing";
import { firstKeyConfig } from "@mod/first-key/testing";
import { frontRelayConfig, wireCertificates } from "@mod/front-relay/testing";
import { httpConfig } from "@mod/http/testing";
import { issuerConfig } from "@mod/issuer/testing";
import { kernelConfig } from "@mod/kernel";
import { keysConfig } from "@mod/keys/testing";
import { fakeKms, kmsServer } from "@mod/keys-kms/testing";
import { fakeRelay } from "@mod/mail-smtp/testing";
import { parConfig } from "@mod/par/testing";
import { tokensConfig } from "@mod/tokens/testing";
import { webauthnConfig } from "@mod/webauthn/testing";
import { stopAll } from "../../lifecycle/lifecycle.ts";

/** How long an app may take to listen once run. */
const bootMs = 20_000;

/** A registry's client, as `clients-registry` reads a record. */
export type RegistryClient = Readonly<Record<string, unknown>> & { readonly id: string };

/** What a scene is: where it is reached, who its clients are, and how it differs from the pattern. */
export interface SceneSpec {
	/** The host the issuer's front is named by, and the address it listens on: the suite's containers reach this machine by them (`hostForSuite`). */
	readonly host: string;
	readonly listen: string;
	/** The login screen's origin: the authorization's screen, WebAuthn's origin and RP id. */
	readonly screen: string;
	/** The clients the operator registers, in a signed registry version. */
	readonly clients: readonly RegistryClient[];
	/** PAR's `jar-max-lifetime` where a run sets one (B's 360 seconds), the module's default unless given. */
	readonly parJarMaxLifetime?: string;
}

/** The scene started: the issuer's origin, the certificate its front answers with, and its stop. */
export interface Scene {
	readonly issuer: string;
	/** The issuer's front's certificate, as PEM: a client of the scene trusts it alone. */
	readonly certificate: string;
	/** What each app wrote so far, for a failure to show. */
	readonly output: () => string;
	stop(): Promise<void>;
}

/** A key's ARN in the fake KMS: AWS's documentation account, never a real one. */
const arn = (id: string) => `arn:aws:kms:eu-west-1:111122223333:key/${id}`;
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;

/**
 * TLS 1.2's ECDHE suites with AES-GCM that BCP 195 recommends (RFC 9325 §4.2), as the suite's own TLS
 * client offers them; the certificate is P-256, so its ECDSA pair is the one that shakes hands. TLS
 * 1.3's suites are Node's, every one of them.
 */
const bcp195 = [
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384",
].join(":");

/** The one sender the apps are told of (RFC 5737's documentation range): the rate limits count every request as its. */
export const sender = "192.0.2.10";

/** The files the operator publishes for an issuer at the root, by their paths: the discovery documents and the key sets. */
const publishedFiles = [
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/jwks.json",
	"/core-keys.json",
];

/**
 * Starts the scene; a start that fails stops what it started. The pattern's differences: the spec's
 * (its clients, its screen, PAR's `jar-max-lifetime` where given), `sign-up` added, the memory store, and one
 * sender for every request.
 */
export async function startScene(spec: SceneSpec): Promise<Scene> {
	const stops: (() => Promise<unknown>)[] = [];
	const runs: { readonly name: string; readonly run: Running }[] = [];
	const output = () => runs.map(({ name, run }) => `--- ${name}\n${run.out()}`).join("\n");
	/** Every stop, the last first, each tried though one before it failed; their failures told together. */
	const stop = async () => {
		const problems = await stopAll(stops.splice(0));
		if (problems.length > 0) throw new AggregateError(problems, "the scene did not stop whole");
	};
	const run = async (
		name: string,
		dir: string,
		file: string,
		config: unknown,
		env: Readonly<Record<string, string>>,
		args: readonly string[] = [],
	) => {
		// Split as an operator writes it: each variable `.env.example` names in the environment, the rest in the local layer.
		const { env: variables, local } = await asOperator(dir, config as Record<string, unknown>);
		const started = await running(dir, file, local, { ...variables, ...env }, args);
		runs.push({ name, run: started });
		stops.push(async () => started.stop());
		return started;
	};
	try {
		const dir = await mkdtemp(join(tmpdir(), "interop-oidf-scene-"));
		stops.push(async () => rm(dir, { recursive: true, force: true }));

		// The outside systems the Core reaches, as fakes.
		const certificates = await wireCertificates();
		stops.push(async () => certificates.remove());
		const kms = await kmsServer(
			fakeKms({
				[arn("authority")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
				[arn("core")]: { key: p256(), spec: "ECC_NIST_P256", usage: "SIGN_VERIFY" },
				[arn("sealing")]: { key: p256(), spec: "ECC_NIST_P256", usage: "KEY_AGREEMENT" },
			}).kms,
		);
		stops.push(async () => kms.close());
		const relay = await fakeRelay();
		stops.push(async () => relay.close());
		const empty = join(dir, "empty");
		await writeFile(empty, "");
		// The Core's process takes KMS's endpoint, and no credential or file of the account's.
		const aws = {
			AWS_ENDPOINT_URL_KMS: kms.url,
			AWS_ACCESS_KEY_ID: "AKIDTESTONLY",
			AWS_SECRET_ACCESS_KEY: "test-only",
			AWS_CONFIG_FILE: empty,
			AWS_SHARED_CREDENTIALS_FILE: empty,
			AWS_EC2_METADATA_DISABLED: "true",
		};
		const key = publisherKey();
		const registryFile = join(dir, "clients.jws");
		const version = { v: 1, version: 1, issuedAt: 1_700_000_000, clients: spec.clients };
		await writeFile(registryFile, `${signedBy(key, version)}\n`);

		// The issuer's front first: its origin is the issuer, which the Core's configuration names.
		const frontPort = await freePort();
		const docs = join(dir, "published");
		const tls = await selfSigned(spec.host, join(dir, "tls"));
		const edge: Front = await startFront({
			upstream: () => `http://127.0.0.1:${frontPort}`,
			publicHost: spec.host,
			listen: spec.listen,
			// Every client reaches the front from this machine, whose loopback the Front takes for its
			// trusted proxy: one sender, a documentation address, is told for all of them.
			sender: sender,
			// TLS 1.2 at least, its suites BCP 195's alone: the edge a FAPI deployment puts there.
			tls: { ...tls, minVersion: "TLSv1.2", ciphers: bcp195 },
			// The publisher's answer, as publish-serve gives it: each file as JSON, GET and HEAD alone,
			// to the screen's pages as its one reader.
			handle: async (request: FrontRequest) => {
				const path = request.url.pathname.replace(/\/$/, "");
				if (!publishedFiles.includes(path)) return undefined;
				const origin = request.headers.origin;
				const shared = {
					Vary: "Origin",
					...(origin === spec.screen ? { "Access-Control-Allow-Origin": origin } : {}),
				};
				if (request.method !== "GET" && request.method !== "HEAD")
					return { status: 405, headers: { ...shared, Allow: "GET, HEAD" } };
				const body = await readFile(join(docs, path)).catch(() => undefined);
				if (body === undefined) return { status: 404, headers: shared };
				return {
					status: 200,
					headers: {
						...shared,
						"Content-Type": "application/json",
						"Content-Length": body.length,
						"Cache-Control": "no-cache",
					},
					...(request.method === "GET" ? { body } : {}),
				};
			},
		});
		stops.push(async () => edge.stop());
		const issuer = edge.origin;

		const corePort = await freePort();
		const core = {
			...kernelConfig(),
			...keysConfig(),
			"keys-kms": {
				region: "eu-west-1",
				keys: [
					{ kid: "test", "key-id": arn("authority") },
					{ kid: "core-test", "key-id": arn("core") },
					{ kid: "seal-test", "key-id": arn("sealing") },
				],
			},
			store: { "accept-volatile": true, "accept-unauthenticated": true },
			"mail-smtp": {
				host: "127.0.0.1",
				port: relay.port,
				security: "none",
				from: "idp@example.invalid",
			},
			...auditConfig({ receivers: ["http"] }),
			...auditHttpConfig(),
			outbound: { allow: ["audit.example"] },
			"clients-registry": { file: registryFile, "publisher-key": key.jwk, "min-version": 1 },
			...webauthnConfig({ "rp-id": new URL(spec.screen).hostname, origins: [spec.screen] }),
			...issuerConfig({ url: issuer }),
			...authorizeConfig({ "screen-url": `${spec.screen}/authorize` }),
			...firstKeyConfig({ "mail-link": `${spec.screen}/first-key` }),
			...tokensConfig({ revocation: "denylist" }, { subjects: "checked" }),
			...dpopConfig({ nonce: { ...dpopConfig().dpop.nonce, required: "as" } }),
			...(spec.parJarMaxLifetime === undefined
				? {}
				: parConfig({ "jar-max-lifetime": spec.parJarMaxLifetime })),
			"users-local": { "password-work": "scrypt:10,8,1,32,16" },
			"transparency-local": { origin: spec.screen },
			...httpConfig({ port: corePort, "public-origin": issuer, "trusted-proxies": ["127.0.0.1"] }),
			...coreWireConfig(certificates),
		};
		const coreApp = await generated({
			pattern: "nextgen-core",
			add: ["@mod/sign-up"],
			axes: { "@mod/store": "@mod/store" },
		});
		stops.push(async () => coreApp.remove());
		const coreRun = await run("nextgen-core", coreApp.dir, "src/main.ts", core, aws);
		if (!(await listening(corePort, coreRun, bootMs)))
			throw new Error(`nextgen-core did not listen on ${corePort}:\n${output()}`);

		// What the operator publishes, written by the Core app's own entries.
		for (const entry of ["src/discovery-publish.ts", "src/keys-publish.ts"]) {
			const wrote = await run(entry, coreApp.dir, entry, core, aws, [docs]);
			if ((await wrote.exited) !== 0) throw new Error(`${entry} failed:\n${output()}`);
		}

		const frontApp = await generated({ pattern: "nextgen-front" });
		stops.push(async () => frontApp.remove());
		const front = {
			...kernelConfig(),
			...httpConfig({
				port: frontPort,
				"public-origin": issuer,
				"trusted-proxies": ["127.0.0.1"],
			}),
			...frontRelayConfig(certificates, { "core-port": corePort }),
		};
		const frontRun = await run("nextgen-front", frontApp.dir, "src/main.ts", front, {});
		if (!(await listening(frontPort, frontRun, bootMs)))
			throw new Error(`nextgen-front did not listen on ${frontPort}:\n${output()}`);

		return { issuer, certificate: tls.cert, output, stop };
	} catch (error) {
		// The start's own failure first; any stop that failed after it, beside it.
		const problems = await stopAll(stops.splice(0));
		if (problems.length > 0) throw new AggregateError([error, ...problems], String(error));
		throw error;
	}
}
