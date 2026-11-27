/** A generated app from a composition: its entries, configuration from the fragments, the network declaration and the guide. */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { configFiles, entriesOf, kernel, mainSource } from "@mod/app-entries";
import { type Ask, askedOf } from "./asked.ts";
import {
	applicationConf,
	envExample,
	fragmentsIn,
	localConfExample,
	settingsOf,
	writtenOf,
} from "./fragments.ts";
import { networkJson, type Process, wordsOf } from "./network.ts";

/** A package as the caller read it: its name, its directory and its manifest. */
export interface Known {
	readonly name: string;
	readonly dir: string;
	readonly manifest: Readonly<Record<string, unknown>>;
}

/** What to write: the composition, what it reaches, its companions, the promises it requires, and its guide's own text. */
export interface App {
	/** The modules composed, in order, as `combinations` composes them. */
	readonly modules: readonly string[];
	/** Every package the composition reaches, in order, a module or not: fragments, `asks` and words are read over these. */
	readonly reached: readonly string[];
	/** Programs of their own the app runs beside it, each a companion with one `bin`. */
	readonly companions: readonly string[];
	/** The promises the app requires, written in `promises.required`. */
	readonly required: readonly string[];
	readonly known: (name: string) => Known | undefined;
	/** What the app's manifest depends on a package as. */
	readonly dependency: (known: Known) => string;
	readonly guide: { readonly title: string; readonly use: string; readonly card: string };
}

const paths = {
	application: "config/application.conf",
	local: "config/local.conf",
	localExample: "config/local.conf.example",
	main: "src/main.ts",
};
/** The owner of `promises.required`, the one value the app writes: required promises need it composed. */
const promisesPackage = "@mod/promises";
const gitIgnored = [
	"node_modules/",
	"config/local*.conf",
	".env",
	".env.*",
	"!.env.example",
	"*.pem",
	"*.key",
	"*.jwk",
];
const run = (file: string) => `node --env-file-if-exists=.env ${file}`;

/** A target that is missing or empty; one that holds anything is refused, never overwritten. */
async function vacant(target: string) {
	const held = await readdir(target).catch((error: NodeJS.ErrnoException) => {
		if (error.code === "ENOENT") return [];
		if (error.code === "ENOTDIR") throw new Error(`${target} is not a directory`);
		throw error;
	});
	if (held.length > 0) throw new Error(`${target} is not empty`);
}

const knownOf = (app: App, name: string) => {
	const known = app.known(name);
	if (!known) throw new Error(`${name}: not a package the caller knows`);
	return known;
};

/** Each companion's one bin, as its manifest names it; refuses one that is no companion or has no bin, or several. */
function companionsOf(app: App) {
	return app.companions.map((name) => {
		const known = knownOf(app, name);
		const bins = Object.entries((known.manifest.bin ?? {}) as Record<string, string>);
		const [bin] = bins;
		if (known.manifest.kind !== "companion") throw new Error(`${name}: not a companion`);
		if (bins.length !== 1 || bin === undefined) throw new Error(`${name}: not one bin`);
		return { known, script: bin[0], file: `node_modules/${name}/${bin[1].replace(/^\.\//, "")}` };
	});
}

/** The workspace packages a package depends on, it first, each once, as far as the caller knows them. */
function closureOf(app: App, root: Known): Known[] {
	const held: Known[] = [];
	const walk = (known: Known) => {
		if (held.some((k) => k.name === known.name)) return;
		held.push(known);
		for (const dep of Object.keys((known.manifest.dependencies ?? {}) as object)) {
			const next = app.known(dep);
			if (next) walk(next);
		}
	};
	walk(root);
	return held;
}

/** Fills a file of `templates/` by its `{{name}}` marks. */
async function filled(template: string, fill: Readonly<Record<string, string>>) {
	const text = await readFile(join(import.meta.dirname, "..", "templates", template), "utf8");
	return text.replace(/\{\{(\w+)\}\}/g, (all, key: string) => fill[key] ?? all);
}

/** The app's files, by path, made before any is written; refuses a script or a path two would write, naming both. */
export async function appFiles(app: App): Promise<Record<string, string>> {
	if (app.required.length > 0 && !app.reached.includes(promisesPackage)) {
		throw new Error(
			`promises required (${app.required.join(", ")}) where ${promisesPackage} is not composed`,
		);
	}
	const reached = app.reached.map((name) => knownOf(app, name));
	const fragments = await fragmentsIn(reached.map((k) => k.dir));
	const settings = settingsOf(fragments);
	const keys = {
		read: Object.fromEntries(settings.map((s) => [s.key, s.env])),
		severalLines: writtenOf(fragments)
			.filter((w) => w.severalLines)
			.map((w) => w.key),
		local: paths.local,
	};
	const declaring = reached.map((k) => ({ name: k.name, appEntries: k.manifest.appEntries }));
	const entries = await entriesOf(app.modules, (name) => name, run, keys, declaring);
	const companions = companionsOf(app);
	const scripts: Record<string, string> = { start: run(paths.main) };
	for (const [script, line] of [
		...Object.entries(entries.scripts),
		...companions.map((c) => [c.script, `node ${c.file}`] as const),
	]) {
		if (script in scripts) throw new Error(`two scripts named ${script}`);
		scripts[script] = line;
	}
	const depended = [kernel, configFiles, ...app.modules, ...app.companions].map((n) =>
		knownOf(app, n),
	);
	const dependencies = Object.fromEntries(depended.map((k) => [k.name, app.dependency(k)]));
	const processes: Process[] = [
		{ name: "app", start: "start", entries: Object.keys(entries.scripts), words: wordsOf(reached) },
		...companions.map((c) => ({
			name: c.script,
			start: c.script,
			words: wordsOf(closureOf(app, c.known)),
		})),
	];
	const asked = askedOf(
		app.reached,
		reached.map((k) => ({
			name: k.name,
			asks: k.manifest.asks as readonly Ask[] | undefined,
			adapts: k.manifest.adapts as string | undefined,
			registersAs: k.manifest.registersAs as string | undefined,
		})),
	);
	const own: Record<string, string> = {
		"package.json": `${JSON.stringify({ name: "auth-provider-app", private: true, type: "module", scripts, dependencies }, null, "\t")}\n`,
		[paths.main]: await mainSource(app.modules, (name) => name, keys),
		[paths.application]: applicationConf(fragments, app.required),
		[paths.localExample]: localConfExample(fragments),
		".env.example": envExample(settings),
		"network.json": networkJson(processes),
		".gitignore": `${gitIgnored.join("\n")}\n`,
		"README.md": await filled("readme.md", {
			...app.guide,
			chosen: asked.chosen.join("\n") || "- Nothing beyond the settings below.",
			decides: asked.decides.join("\n") || "- None.",
			settings: settings.map((s) => `| \`${s.key}\` | \`${s.env}\` |`).join("\n"),
			written:
				writtenOf(fragments)
					.map((w) => `- \`${w.key}\``)
					.join("\n") || "- None.",
			required: app.required.map((p) => `- \`${p}\``).join("\n") || "- None.",
			scripts: Object.keys(scripts)
				.map((s) => `- \`pnpm ${s}\``)
				.join("\n"),
			cards: depended
				.map((k) => `- \`${k.name}\`: \`node_modules/${k.name}/README.md\``)
				.join("\n"),
		}),
	};
	for (const path of Object.keys(entries.files)) {
		if (path in own) throw new Error(`the app's entries and app-output both write ${path}`);
	}
	return { ...own, ...entries.files };
}

/** Writes the app into a missing or empty target, every file made before any is written. */
export async function writeApp(given: string, app: App): Promise<void> {
	// An empty name would be the current directory, whatever it holds: never a target.
	if (given.trim() === "") throw new Error("no target named");
	const target = resolve(given);
	await vacant(target);
	const files = await appFiles(app);
	for (const [path, text] of Object.entries(files)) {
		await mkdir(dirname(join(target, path)), { recursive: true });
		await writeFile(join(target, path), text);
	}
}
