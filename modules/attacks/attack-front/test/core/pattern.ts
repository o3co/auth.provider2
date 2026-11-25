/**
 * The default pattern's seed (M4): a whole Core of the workspace's modules, composed by `combinations`,
 * configured by each module's `./testing`, in one process with no outside system. It moves to the
 * pattern's package once its shape settles (the coordinator, 2026-11-26); the operator's HOCON sections
 * come in there.
 *
 * Interim, until worker-3's fix of refresh's boot lands (the dependency cycle refresh ↔ passkeys
 * through `passkeyRemovals`, and the transparency state's `families`, which no module owns): `interim`
 * below leaves refresh and refresh-store out, stands in for `delegation` and owns `families`. Take it
 * out whole when that fix lands; F-14 and F-20 wait for it.
 *
 * The store is the memory one, which takes neither durability nor authentication, so it is told to
 * accept both: the store-write promise is outside the harness's claims.
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { workspacePackages } from "@mod/workspace-packages";

const root = fileURLToPath(new URL("../../../../../", import.meta.url));

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

/** The features the default pattern composes, beside those they need. */
export const features = scoped([
	"authorize",
	"par",
	"dpop",
	"approvals",
	"passkeys",
	"passkey-management",
	"sign-up",
	"client-credentials",
	"authorize-claims",
	"resource-indicators",
	"discovery",
	"oidc",
]);

/**
 * Each axis's choice: the wire for http, and in-process places for the rest, an owner chosen for its
 * own axis where its adapters reach an outside system (store: redis; mail: SMTP; clients: a signed
 * registry file; keys: KMS).
 */
export const axes = Object.fromEntries(
	Object.entries({
		http: "core-wire",
		keys: "keys-local",
		users: "users-local",
		transparency: "transparency-local",
		audit: "audit-stdout",
		metrics: "metrics-log",
		store: "store",
		mail: "mail",
		clients: "clients",
	}).map(([axis, choice]) => [`@mod/${axis}`, `@mod/${choice}`]),
);

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
	/** More features beside `features`, or fewer (a name prefixed `-`, which no need may bring back). */
	readonly change?: readonly string[];
}

/** A mail the Core sent, as `mail`'s preparer made it. */
export type SentMail = Record<string, unknown>;

/** The default pattern's modules and configuration; `sent` receives each mail the Core sends. */
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
	const modules = [...(await interim.modules(defineModule))];
	for (const name of names) {
		if (interim.out.includes(name)) continue;
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

/** The interim (the note above): what it leaves out, and its stand-ins, `delegation` and `families`' owner. */
const interim = {
	out: scoped(["refresh", "refresh-store"]),
	modules: interimModules,
};

// biome-ignore lint/suspicious/noExplicitAny: the kernel's defineModule, typed by the entry imported.
async function interimModules(defineModule: any) {
	const { delegation } = await entry("@mod/refresh");
	const { stateOwners } = await entry("@mod/transparency");
	const { spaces } = await entry("@mod/store");
	const { frameParts } = await entry("@mod/transparency-frames");
	const space = {
		name: "families-owner.flows",
		guarantees: ["no-eviction", "durable", "replicated", "confirmed-reads", "authenticated"],
		subjectData: "retained",
	};
	return [
		defineModule(
			{ name: "delegation-stand-in", replicaSafe: true, takes: [] },
			// biome-ignore lint/suspicious/noExplicitAny: as above.
			(m: any) => [m.provide(delegation).by(() => ({ lifetimeMs: 86_400_000 }))],
		),
		defineModule(
			{ name: "families-owner", replicaSafe: true, takes: [] },
			// biome-ignore lint/suspicious/noExplicitAny: as above.
			(m: any) => [
				m.contribute(spaces).by(() => space),
				m.contribute(frameParts).by(() => ({ name: "families", space })),
				m.contribute(stateOwners).by(() => ({
					name: "families",
					holds: ["families"],
					parts: ["families"],
					records: () => [{ part: "families", name: "state" }],
					read: () => ({ families: {} }),
					write: () => [undefined],
				})),
			],
		),
	];
}

const pem = () =>
	generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
		type: "pkcs8",
		format: "pem",
	});

/** Each composed module's section, from its `./testing` where it has one. */
// biome-ignore lint/suspicious/noExplicitAny: the kernel's kernelConfig, typed by the entry imported.
async function configOf(spec: PatternSpec, kernelConfig: any) {
	const testing = (name: string) => entry(name, "./testing");
	const { keysConfig } = await testing("@mod/keys");
	const { webauthnConfig } = await testing("@mod/webauthn");
	const { issuerConfig } = await testing("@mod/issuer");
	const { authorizeConfig } = await testing("@mod/authorize");
	const { passkeyManagementConfig } = await testing("@mod/passkey-management");
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
		...keysConfig(),
		"keys-local": { keys: ["test", "core-test", "seal-test"].map((kid) => ({ kid, pem: pem() })) },
		...webauthnConfig({ "rp-id": new URL(spec.screen).hostname, origins: [spec.screen] }),
		...issuerConfig({ url: spec.origin }),
		...authorizeConfig({ "screen-url": `${spec.screen}/authorize` }),
		...passkeyManagementConfig({ "mail-link": `${spec.screen}/first-key` }),
		...tokensConfig({ revocation: "denylist" }, { subjects: "checked" }),
		// The nonce asked at the authorization server, the module's default, not the tests' `never`.
		...dpopConfig({ nonce: { ...dpopConfig().dpop.nonce, required: "as" } }),
		...clientsConfig(spec.clients),
		...auditConfig({ receivers: ["stdout"] }),
		// The claim the harness attacks must hold, or boot is refused (the design note, §1). Claim 2
		// (`front-compromise-client-token`) joins once a module stands holding it: today none does,
		// so it holds in no composition (m0-notes, 2026-11-26).
		promises: { required: [promiseNames.newAuthorization] },
		"users-local": { "password-work": "scrypt:10,8,1,32,16" },
		"transparency-local": { origin: spec.screen },
		// The wire's port; the public origin the issuer names its endpoints on; the Fronts, on this host,
		// whose declared source the Core reads (each step declares its own).
		...httpConfig({ "public-origin": spec.origin, "trusted-proxies": ["127.0.0.1"] }),
		...coreWireConfig(spec.certificates),
	};
}
