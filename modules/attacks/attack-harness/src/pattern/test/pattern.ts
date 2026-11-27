/**
 * The harness's Core: `nextgen-core`'s selection, as create-app composes the pattern, with what the
 * harness attacks beside it, configured by each module's `./testing`, in one process with no outside
 * system.
 *
 * The store is the memory one, which takes neither durability nor authentication, so it is told to
 * accept both: the store-write promise is outside the harness's claims.
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { patternNamed, selectionOf } from "@mod/create-app";
import { workspacePackages } from "@mod/workspace-packages";

const root = fileURLToPath(new URL("../../../../../../", import.meta.url));

/** Each workspace package's directory, by its name, as the workspace's definition places them. */
const packages = new Map(workspacePackages(root).map((p) => [p.name, p.dir]));

/** Whether a workspace package is a module: one with a composition definition (`./module`). */
const isModule = (name: string) => manifestOf(name).exports?.["./module"] !== undefined;

const manifestOf = (name: string) => {
	const dir = packages.get(name);
	return dir === undefined ? {} : JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
};
const isFeature = (name: string) => manifestOf(name).kind === "feature";
const isBridge = (name: string) => manifestOf(name).joins !== undefined;

/** A workspace package's entry, imported by its path: the pattern composes what `combinations` names. */
// biome-ignore lint/suspicious/noExplicitAny: an entry's exports are read by name, as the generated app's entry does.
export async function entry(name: string, sub = "."): Promise<any> {
	const dir = packages.get(name);
	if (dir === undefined) throw new Error(`no package ${name}`);
	const exports = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).exports;
	return import(join(dir, exports[sub]));
}

const scoped = (names: readonly string[]) => names.map((name) => `@mod/${name}`);

const core = patternNamed("nextgen-core");
if (core === undefined) throw new Error("create-app has no nextgen-core");

/**
 * `nextgen-core`'s selection, with sign-up and client-credentials beside it, which the harness
 * attacks and the pattern leaves to the operator; and in-process places for the five axes whose
 * pattern adapters reach an outside system: keys-local for KMS, audit-stdout for the audit receiver,
 * and the owner itself for store (Redis), mail (SMTP) and clients (a signed registry file).
 */
const selection = selectionOf(core, {
	add: scoped(["sign-up", "client-credentials"]),
	axes: Object.fromEntries(
		Object.entries({
			keys: "keys-local",
			audit: "audit-stdout",
			store: "store",
			mail: "mail",
			clients: "clients",
		}).map(([axis, choice]) => [`@mod/${axis}`, `@mod/${choice}`]),
	),
});

/** The features the harness's Core composes, beside those they need. */
export const features: readonly string[] = [
	...(selection.features[core.name] as readonly string[]),
	...(selection.add as readonly string[]),
];

/** Each axis's choice. */
export const axes = selection.axes as Readonly<Record<string, string>>;

/** Where the Core is reached and what it is: the wire's certificate files, its public origin and issuer. */
export interface PatternSpec {
	readonly certificates: {
		readonly authority: string;
		readonly core: { readonly cert: string; readonly key: string };
	};
	readonly origin: string;
	/** The login screen's origin: the authorization's screen, WebAuthn's origin and RP id, the mail's link. */
	readonly screen: string;
	/** The clients the operator registers, as `clients`' `registered` takes them. */
	readonly clients: readonly unknown[];
	/**
	 * The clients of a registry version its publisher signed (each record with its `version`): a source
	 * marked signed stands in for clients-registry's signed file, whose signature the harness does not attack.
	 */
	readonly signedClients?: readonly { readonly id: string }[];
	/** More features beside `features`, or fewer (a name prefixed `-`, which no need may bring back). */
	readonly change?: readonly string[];
	/** More promises the composition must hold, beside the claims the harness attacks: boot refused otherwise. */
	readonly required?: readonly string[];
	/**
	 * Of the claims the harness attacks, those this composition need not hold: for a step showing a
	 * module's own refusal behind the claim's boot check.
	 */
	readonly released?: readonly string[];
	/** What the wire does to a Front instance that sent a violation (core-wire's `on-violation`), `notify` unless said. */
	readonly onViolation?: "notify" | "cut";
	/** The operator's `outbound` section (outbound's words), where a step's Core reaches a server of the harness. */
	readonly outbound?: Readonly<Record<string, unknown>>;
	/**
	 * Users brought from another IdP, as an operator's import run hands them to users' `usersImport`
	 * once the Core started: a subject holding no passkey.
	 */
	readonly seeds?: readonly {
		readonly subject: string;
		readonly identifier?: string;
		readonly verifiedEmail?: string;
	}[];
	/**
	 * The Core generation before this one's key, as PKCS#8 PEM the test made and keeps: the ring then
	 * holds both, this Core running as generation 2 and signing with its own; the earlier one verifies.
	 * One generation unless given.
	 */
	readonly previousCoreKey?: string;
	/**
	 * The installation's id and the reset instruction's signer sets (transparency-local's
	 * `installation` and `reset-keys`, V22): a reset placed only where given.
	 */
	readonly reset?: {
		readonly installation: string;
		readonly keys: readonly {
			readonly version: number;
			readonly keys: readonly Record<string, unknown>[];
		}[];
	};
}

/** A mail the Core sent, as `mail`'s preparer made it. */
export type SentMail = Record<string, unknown>;

/** The harness's Core's modules and configuration; `sent` receives each mail the Core sends. */
export async function pattern(spec: PatternSpec, sent: (mail: SentMail) => void) {
	const { composed } = await entry("@mod/combinations");
	const { defineModule, kernelConfig } = await entry("@mod/kernel");
	const chosen = [
		...features.filter((name) => !spec.change?.includes(`-${name}`)),
		...(spec.change ?? []).filter((name) => !name.startsWith("-")),
	];
	const all: string[] = composed({ features: { core: chosen }, axes });
	// A name taken out must have come and be taken out whole: a bridge comes back with its modules, so
	// it is filtered after; one another module needs comes back, and the composition is refused here.
	const out = (spec.change ?? [])
		.filter((name) => name.startsWith("-"))
		.map((name) => name.slice(1));
	const unknown = out.filter((name) => !all.includes(name) && !features.includes(name));
	if (unknown.length > 0) throw new Error(`not composed, so not taken out: ${unknown.join(", ")}`);
	const names = all.filter((name) => !out.includes(name));
	const needed: string[] = composed({ features: { core: names.filter(isFeature) }, axes });
	const back = out.filter((name) => needed.includes(name) && !isBridge(name));
	if (back.length > 0) throw new Error(`taken out, but needed: ${back.join(", ")}`);

	const mail = await entry("@mod/mail");
	const capture = defineModule(
		{ name: "mail-capture", replicaSafe: false, takes: mail.preparerTakes },
		// biome-ignore lint/suspicious/noExplicitAny: the kernel's builder, typed by the entry imported.
		(m: any) => [
			// biome-ignore lint/suspicious/noExplicitAny: as above.
			m.provide(mail.mail).by(async (c: any) => {
				const prepare = await mail.preparer(c);
				return {
					send: async (input: unknown) => {
						sent(prepare(input).message);
						return "sent";
					},
				};
			}),
		],
	);
	const modules = [];
	if (spec.signedClients !== undefined && spec.signedClients.length > 0) {
		const { clientSources } = await entry("@mod/clients");
		const signed = spec.signedClients;
		modules.push(
			defineModule(
				{ name: "signed-registry", replicaSafe: true, takes: [] },
				// biome-ignore lint/suspicious/noExplicitAny: the kernel's builder, typed by the entry imported.
				(m: any) => [
					m.contribute(clientSources).by(() => ({
						signed: true,
						find: async (id: string) => signed.find((client) => client.id === id),
						listed: async () => signed,
					})),
				],
			),
		);
	}
	for (const name of names) {
		modules.push(name === "@mod/mail" ? capture : (await entry(name, "./module")).default);
	}
	// A section for a module not composed refuses boot: only the composed modules' are kept.
	const config = Object.fromEntries(
		Object.entries(await configOf(spec, kernelConfig)).filter(
			([section]) => !isModule(`@mod/${section}`) || names.includes(`@mod/${section}`),
		),
	);
	return { names, modules, config };
}

const pem = () =>
	generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	});

/** The kid of the Core's key of the generation before, where the spec gives one. */
export const previousKid = "core-previous";

/** The keys section: the Core's ring of one generation, or of two where the spec gives the earlier key. */
// biome-ignore lint/suspicious/noExplicitAny: keys' keysConfig, typed by the entry imported.
function ringOf(spec: PatternSpec, keysConfig: any) {
	if (spec.previousCoreKey === undefined) return keysConfig();
	return keysConfig({
		core: {
			generation: 2,
			keys: [
				{ generation: 1, kid: previousKid, alg: "ES256" },
				{ generation: 2, kid: "core-test", alg: "ES256" },
			],
		},
	});
}

/** Each composed module's section, from its `./testing` where it has one. */
// biome-ignore lint/suspicious/noExplicitAny: the kernel's kernelConfig, typed by the entry imported.
async function configOf(spec: PatternSpec, kernelConfig: any) {
	const testing = (name: string) => entry(name, "./testing");
	const { keysConfig } = await testing("@mod/keys");
	const { webauthnConfig } = await testing("@mod/webauthn");
	const { issuerConfig } = await testing("@mod/issuer");
	const { authorizeConfig } = await testing("@mod/authorize");
	const { firstKeyConfig } = await testing("@mod/first-key");
	const { tokensConfig } = await testing("@mod/tokens");
	const { dpopConfig } = await testing("@mod/dpop");
	const { clientsConfig } = await testing("@mod/clients");
	const { storeConfig } = await testing("@mod/store");
	const { auditConfig } = await testing("@mod/audit");
	const { coreWireConfig } = await testing("@mod/core-wire");
	const { httpConfig } = await testing("@mod/http");
	const { promiseNames } = await entry("@mod/promises");
	return {
		...kernelConfig(),
		...storeConfig({ "accept-unauthenticated": true }),
		...ringOf(spec, keysConfig),
		"keys-local": {
			keys: [
				...["test", "core-test", "seal-test"].map((kid) => ({ kid, pem: pem() })),
				...(spec.previousCoreKey === undefined
					? []
					: [{ kid: previousKid, pem: spec.previousCoreKey }]),
			],
		},
		...webauthnConfig({ "rp-id": new URL(spec.screen).hostname, origins: [spec.screen] }),
		...issuerConfig({ url: spec.origin }),
		...authorizeConfig({ "screen-url": `${spec.screen}/authorize` }),
		...firstKeyConfig({ "mail-link": `${spec.screen}/first-key` }),
		...tokensConfig({ revocation: "denylist" }, { subjects: "checked" }),
		// The nonce asked at the authorization server, the module's default, not the tests' `never`.
		...dpopConfig({ nonce: { ...dpopConfig().dpop.nonce, required: "as" } }),
		...clientsConfig(spec.clients),
		...auditConfig({ receivers: ["stdout"] }),
		// The claims the harness attacks (1 and 2) must hold, or boot is refused (the design note, §1).
		promises: {
			required: [
				...[promiseNames.newAuthorization, promiseNames.clientToken].filter(
					(name) => !spec.released?.includes(name),
				),
				...(spec.required ?? []),
			],
		},
		...(spec.outbound === undefined ? {} : { outbound: spec.outbound }),
		"users-local": { "password-work": "scrypt:10,8,1,32,16" },
		"transparency-local": {
			origin: spec.screen,
			...(spec.reset === undefined
				? {}
				: { installation: spec.reset.installation, "reset-keys": spec.reset.keys }),
		},
		// The wire's port; the public origin the issuer names its endpoints on; the Fronts, on this host,
		// whose declared source the Core reads (each step declares its own).
		...httpConfig({ "public-origin": spec.origin, "trusted-proxies": ["127.0.0.1"] }),
		...coreWireConfig(
			spec.certificates,
			spec.onViolation === undefined ? {} : { "on-violation": spec.onViolation },
		),
	};
}
