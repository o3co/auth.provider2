/** Node's settings for a process: its permission flags, made from what it may do and its configuration. */
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ProcessPermissions } from "./process.ts";
import type { ConfigReads } from "./reads.ts";

/** How the process is held: `enforce` refuses what is not granted, `audit` lets it through and tells, `off` holds nothing. */
export type Mode = "enforce" | "audit" | "off";
export const modes: readonly Mode[] = ["enforce", "audit", "off"];

export interface NodeInputs {
	readonly mode: Mode;
	/** The configuration as loaded, and what the load read. */
	readonly tree: unknown;
	readonly reads: ConfigReads;
	readonly env: Readonly<Record<string, string | undefined>>;
	/** The home directory, as `~/` in a variable's default stands for it: as {@link homeOf} takes it. */
	readonly home: string;
	/** Where relative values resolve, as the modules read them. */
	readonly cwd: string;
	/** The app's own directory, by its real path, wherever it was moved since it was generated: its first code root. */
	readonly appRoot: string;
	/** Whether this Node takes `--allow-net` (Node 24 does not, and holds no network). */
	readonly allowsNet: boolean;
}

/** The flags, and the packages whose `forks` the child-process grant is for; or where a value is that cannot be a grant, and why. */
export type NodeSettings =
	| { readonly argv: readonly string[]; readonly childFor: readonly string[] }
	| { readonly refused: { readonly where: string; readonly reason: string } };

/**
 * The home directory as the environment's readers take it (the AWS SDK among them): `HOME`, then
 * `USERPROFILE`, then `HOMEDRIVE` and `HOMEPATH` (`C:` and the separator where no drive is set), then
 * the system's.
 */
export function homeOf(
	env: Readonly<Record<string, string | undefined>>,
	system: string,
	separator: string,
): string {
	if (env.HOME) return env.HOME;
	if (env.USERPROFILE) return env.USERPROFILE;
	if (env.HOMEPATH) return `${env.HOMEDRIVE ?? `C:${separator}`}${env.HOMEPATH}`;
	return system;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** The values at a key path of a tree, `*` each element of a list there; none where the path holds none. */
export function atKeyPath(tree: unknown, path: string): unknown[] {
	let at: unknown[] = [tree];
	for (const word of path.split(".")) {
		at = at.flatMap((value) => {
			if (word === "*") return Array.isArray(value) ? value : [];
			return isObject(value) && Object.hasOwn(value, word) ? [value[word]] : [];
		});
	}
	return at;
}

/** The strings at a key path of a section; any other value is no file named. */
export const valuesAt = (section: unknown, path: string): string[] =>
	atKeyPath(section, path).filter(
		(value): value is string => typeof value === "string" && value !== "",
	);

/** A grant Node cannot take: a path holding `*` or `,`, which it reads as its own. */
const ungrantable = (path: string) => path.includes("*") || path.includes(",");

/** Every `node_modules` above a root, where a library may look a package up: never the ancestor itself. */
export function lookupsAbove(root: string): string[] {
	const above: string[] = [];
	for (let dir = dirname(root); ; dir = dirname(dir)) {
		above.push(join(dir, "node_modules"));
		if (dirname(dir) === dir) return above;
	}
}

/**
 * Node's flags for a process: in `enforce` or `audit`, read grants for its code (the app's own directory
 * first, and the lookups above each root), its configuration's reads and probes, the files its packages' keys name, their literal paths and
 * variables' files; the child-process grant where a package's `forks` start one; the network where it
 * reaches it and this Node takes the flag. No write is granted. A value Node cannot take as a grant
 * (holding `*` or `,`) refuses.
 */
export function nodeSettings(process: ProcessPermissions, inputs: NodeInputs): NodeSettings {
	if (inputs.mode === "off") return { argv: [], childFor: [] };
	const reads = new Map<string, string>();
	/** A read granted, and where it came from, which a refusal names instead of the path. */
	const grant = (path: string, from: string) => {
		if (!reads.has(path)) reads.set(path, from);
	};
	for (const root of [inputs.appRoot, ...process.code]) {
		grant(root, "permissions.json");
		for (const above of lookupsAbove(root)) grant(above, "permissions.json");
	}
	for (const path of [...inputs.reads.read, ...inputs.reads.probed])
		grant(resolve(inputs.cwd, path), "APP_CONFIG");
	const childFor: string[] = [];
	const tree = isObject(inputs.tree) ? inputs.tree : {};
	for (const declared of process.declared) {
		const section = tree[declared.section];
		const { read, child } = declared.permissions;
		for (const key of read?.keys ?? [])
			for (const value of valuesAt(section, key))
				grant(resolve(inputs.cwd, value), `${declared.section}.${key}`);
		for (const { path } of read?.paths ?? []) grant(path, declared.package);
		for (const { name, default: fallback, home } of read?.env ?? []) {
			// The value as its reader reads it: `~/` the home directory in the default, and in the value where the reader says so.
			const set = inputs.env[name];
			const given = set !== undefined && set !== "";
			const named = given ? set : fallback;
			const path =
				named?.startsWith("~/") && (!given || home === true)
					? join(inputs.home, named.slice(2))
					: named;
			if (path === undefined || path === "") continue;
			grant(isAbsolute(path) ? path : resolve(inputs.cwd, path), name);
		}
		if (!declared.forks) continue;
		const when = child?.when;
		const holds = when === undefined || atKeyPath(section, when.key).includes(when.is);
		if (holds) childFor.push(declared.package);
	}
	for (const [path, from] of reads)
		if (ungrantable(path))
			return {
				refused: { where: from, reason: "names a path holding * or ,, which Node cannot grant" },
			};
	const argv = [
		inputs.mode === "enforce" ? "--permission" : "--permission-audit",
		...[...reads.keys()].map((path) => `--allow-fs-read=${path}`),
		...(childFor.length > 0 ? ["--allow-child-process"] : []),
		...(process.network && inputs.allowsNet ? ["--allow-net"] : []),
	];
	return { argv, childFor };
}
