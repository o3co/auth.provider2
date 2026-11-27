import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { BootRefused } from "@mod/kernel";
import { type Config, ParseError, parse, ResolveError } from "@o3co/ts.hocon";
import { legacyVariables } from "./legacy-variables.ts";

export interface ConfigSource {
	/** Highest priority first. */
	readonly files: readonly string[];
	readonly env: Readonly<Record<string, string | undefined>>;
}

/**
 * Layers the files, highest priority first, and returns a plain tree. Resolves each file on its
 * own, then layers them, so substitutions reach only env and the same file: a refusal names the
 * file, which the HOCON library's deferred resolution does not tell. Remove when: its ResolveError
 * carries the file (`file`) after a deferred resolve; then resolve the merged layers once, so
 * substitutions cross files again.
 */
export async function loadConfig(source: ConfigSource): Promise<unknown> {
	return treeOf(await layersOf(source.files, setOf(source.env)));
}

const treeOf = (layers: readonly Config[]) => {
	const [first, ...rest] = layers;
	if (first === undefined) return {};
	return rest.reduce((acc, layer) => acc.withFallback(layer), first).toObject();
};

/** The files a load read, and the paths it looked for and found nothing at, each once, in order. */
export interface ConfigReads {
	readonly read: readonly string[];
	readonly probed: readonly string[];
}

/**
 * As `loadConfig`, and what it read: every file, its includes among them, and every path an include
 * looked for and found nothing at (a bare include tries `.properties`, `.json` and `.conf`). A refusal
 * comes with what was read up to it.
 */
export async function loadConfigReading(
	source: ConfigSource,
): Promise<
	| { readonly kind: "loaded"; readonly tree: unknown; readonly reads: ConfigReads }
	| { readonly kind: "refused"; readonly refusal: BootRefused; readonly reads: ConfigReads }
> {
	const read = new Set<string>();
	const probed = new Set<string>();
	const reads = () => ({ read: [...read], probed: [...probed].filter((path) => !read.has(path)) });
	try {
		const layers = await layersOf(source.files, setOf(source.env), { read, probed });
		return { kind: "loaded", tree: treeOf(layers), reads: reads() };
	} catch (error) {
		if (!BootRefused.is(error)) throw error;
		return { kind: "refused", refusal: error, reads: reads() };
	}
}

/**
 * The variables 0.17 bound that `source.env` sets and no file reads, in order; never their values.
 * A file reads the names the HOCON library looks up in the env it is given, and only those.
 */
export async function unreadLegacyVariables(source: ConfigSource): Promise<readonly string[]> {
	const env = setOf(source.env);
	const read = new Set<string>();
	const noted = (name: string | symbol) => {
		if (typeof name === "string") read.add(name);
	};
	const recording = new Proxy(env, {
		get(target, name, receiver) {
			noted(name);
			return Reflect.get(target, name, receiver);
		},
		has(target, name) {
			noted(name);
			return Reflect.has(target, name);
		},
		getOwnPropertyDescriptor(target, name) {
			noted(name);
			return Reflect.getOwnPropertyDescriptor(target, name);
		},
	});
	await layersOf(source.files, recording);
	return Object.keys(env)
		.filter((name) => legacyVariables.has(name) && !read.has(name))
		.sort();
}

/** The boot's warning for the names `unreadLegacyVariables` gives: how many and which; none for none. */
export function legacyVariablesWarning(names: readonly string[]): string | undefined {
	return names.length === 0 ? undefined : `${namedIn017(names)}; see docs/migration.md`;
}

/** How many and which, in the warning's words and the refusal's. */
function namedIn017(names: readonly string[]): string {
	const [count, verb] =
		names.length === 1 ? ["1 variable", "is"] : [`${names.length} variables`, "are"];
	return `${count} named in 0.17 ${verb} set and never read: ${names.join(", ")}`;
}

/** The variable an app's entry reads to choose what the check does: `warn` (unset or empty), `refuse` or `ignore`. */
const modeVariable = "APP_LEGACY_VARIABLES";

/**
 * The boot's check for 0.17's variables left in `source.env`, as `APP_LEGACY_VARIABLES` there says:
 * unset, empty or `warn`, the warning `legacyVariablesWarning` gives, or none; `refuse`, a refused boot
 * naming them where any is set; `ignore`, nothing, as nothing is read. Any other value refuses boot
 * at the variable, never showing it. The names come in order, never their values.
 */
export async function legacyVariablesCheck(source: ConfigSource): Promise<string | undefined> {
	// Empty as unset: an env file or a compose file can write the variable with no value.
	const mode = source.env[modeVariable] || "warn";
	if (mode === "ignore") return undefined;
	if (mode !== "warn" && mode !== "refuse") {
		throw new BootRefused([{ where: modeVariable, reason: "one of warn, refuse or ignore" }]);
	}
	const names = await unreadLegacyVariables(source);
	if (mode === "warn" || names.length === 0) return legacyVariablesWarning(names);
	throw new BootRefused([
		{
			where: "config-files",
			reason: `${namedIn017(names)}; remove them, or set ${modeVariable} to warn or ignore; see docs/migration.md`,
		},
	]);
}

const setOf = (env: ConfigSource["env"]) =>
	Object.fromEntries(
		Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
	);

/** `include package(...)`, refused: its lookups are the library's own, which no reader sees. */
class PackageInclude extends Error {}
const noPackageIncludes = () => {
	throw new PackageInclude("include package(...)");
};
/** Whether an error is, or was raised by, a package include refused. */
const isPackageInclude = (error: unknown): boolean =>
	error instanceof PackageInclude ||
	(error instanceof Error && error.cause !== undefined && isPackageInclude(error.cause));

/**
 * Each file read and parsed on its own with `env`; one that cannot be refuses boot. With `noted`,
 * each path read (an include's among them) and each looked for and missing is noted.
 */
async function layersOf(
	files: readonly string[],
	env: Record<string, string>,
	noted?: { readonly read: Set<string>; readonly probed: Set<string> },
): Promise<Config[]> {
	const reading = (path: string) => {
		try {
			const text = readFileSync(path, "utf8");
			noted?.read.add(path);
			return text;
		} catch (error) {
			// Missing, the library tries the next form; anything else is a read it made all the same.
			if ((error as { code?: unknown }).code === "ENOENT") noted?.probed.add(path);
			else noted?.read.add(path);
			throw error;
		}
	};
	const layers: Config[] = [];
	for (const file of files) {
		noted?.read.add(file);
		const text = await readFile(file, "utf8").catch(() => {
			throw new BootRefused([
				{
					where: file,
					reason:
						"cannot read the configuration file: create it, or leave it out of the files the app reads",
				},
			]);
		});
		try {
			layers.push(
				parse(text, {
					env,
					baseDir: dirname(file),
					readFileSync: reading,
					packageResolver: noPackageIncludes,
				}),
			);
		} catch (error) {
			throw new BootRefused([refusalOf(file, error)]);
		}
	}
	return layers;
}

/** Where a file fails, at its line and column, and why by the kind of failure; never its text. */
function refusalOf(file: string, error: unknown) {
	if (isPackageInclude(error))
		return {
			where: file,
			reason: "include package(...) is not taken: include the file by its path",
		};
	if (error instanceof ParseError) {
		return { where: `${file}:${error.line}:${error.col}`, reason: "not readable as HOCON" };
	}
	if (error instanceof ResolveError) {
		return { where: `${file}:${error.line}:${error.col}`, reason: `cannot resolve ${error.path}` };
	}
	return { where: file, reason: "not readable as HOCON, or a substitution cannot be resolved" };
}
