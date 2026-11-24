import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import ts from "typescript";

/** A rule broken: its id, the place relative to the sdk's root, and what went over. */
export interface Finding {
	readonly id: string;
	readonly place: string;
	readonly what: string;
}

type Manifest = Readonly<Record<string, unknown>> & {
	readonly name?: string;
	readonly kind?: string;
	readonly packageManager?: string;
};
const dependencyFields = [
	"dependencies",
	"peerDependencies",
	"optionalDependencies",
	"devDependencies",
] as const;

const readManifest = (dir: string): Manifest | undefined => {
	const path = join(dir, "package.json");
	return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as Manifest) : undefined;
};
const real = (path: string) => (existsSync(path) ? realpathSync(path) : resolve(path));
/** Whether a path lies under a directory. */
const inside = (dir: string, path: string) => {
	const rel = relative(dir, path);
	return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
};

/**
 * A pnpm-workspace.yaml's top-level settings, each as the text of its value (a scalar, or a block's
 * entries in order) or, for a block of `key: value` entries, those entries; comments left out.
 */
function settingsOf(text: string): Map<string, string | Map<string, string>> {
	const settings = new Map<string, string | Map<string, string>>();
	let open: { key: string; lines: string[] } | undefined;
	const close = () => {
		if (!open) return;
		const entries = open.lines.map((line) => line.match(/^("[^"]*"|[^:\s]+):\s*(.+)$/));
		settings.set(
			open.key,
			open.lines.length > 0 && entries.every((entry) => entry !== null)
				? new Map(entries.map((entry) => [entry?.[1] ?? "", entry?.[2] ?? ""]))
				: open.lines.join("\n"),
		);
		open = undefined;
	};
	for (const raw of text.split("\n")) {
		const line = raw.replace(/\s+#.*$/, "").replace(/^#.*$/, "");
		if (line.trim() === "") continue;
		const top = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/);
		if (top) {
			close();
			if (top[2]) settings.set(top[1] ?? "", top[2]);
			else open = { key: top[1] ?? "", lines: [] };
		} else open?.lines.push(line.trim());
	}
	close();
	return settings;
}

/** The provider workspace's packages, as its pnpm-workspace.yaml's globs (`*` a directory) name them. */
function providerPackages(repo: string): Map<string, Manifest> {
	const globs = settingsOf(readFileSync(join(repo, "pnpm-workspace.yaml"), "utf8")).get("packages");
	const patterns = typeof globs === "string" ? globs.split("\n") : [];
	const packages = new Map<string, Manifest>();
	for (const pattern of patterns.map((line) => line.replace(/^-\s*/, "").replace(/"/g, ""))) {
		let dirs = [repo];
		for (const part of pattern.split("/"))
			dirs = dirs.flatMap((dir) =>
				part === "*"
					? existsSync(dir)
						? readdirSync(dir).map((entry) => join(dir, entry))
						: []
					: [join(dir, part)],
			);
		for (const dir of dirs) {
			const manifest = readManifest(dir);
			if (manifest) packages.set(real(dir), manifest);
		}
	}
	return packages;
}

/** A package's files, dot-named ones too, without node_modules, its symlinks apart. */
function walk(dir: string): { files: string[]; links: string[] } {
	const out = { files: [] as string[], links: [] as string[] };
	for (const entry of readdirSync(dir)) {
		if (entry === "node_modules") continue;
		const path = join(dir, entry);
		const stat = lstatSync(path);
		if (stat.isSymbolicLink()) out.links.push(path);
		else if (stat.isDirectory()) {
			const inner = walk(path);
			out.files.push(...inner.files);
			out.links.push(...inner.links);
		} else out.files.push(path);
	}
	return out;
}

const sourceFile = /\.[cm]?[jt]sx?$/;
/** A test: a file under the package's own `test` directory, or one named `*.test.*`. */
const isTest = (rel: string) => rel.startsWith(`test/`) || /\.test\.[cm]?[jt]sx?$/.test(rel);

/** Every reference a file names: imports, re-exports, import types, dynamic imports, requires and triple-slash ones. */
function referencesOf(text: string) {
	const read = ts.preProcessFile(text, true, true);
	return {
		modules: read.importedFiles.map((file) => file.fileName),
		paths: read.referencedFiles.map((file) => file.fileName),
		types: read.typeReferenceDirectives.map((file) => file.fileName),
		libs: read.libReferenceDirectives.map((file) => file.fileName),
	};
}

/**
 * Checks the sdk (the directory `root`) and its packages (each directory under `packages`) against
 * the provider's workspace (the repository root beside it):
 * - S1: each dependency, in every dependency field apart, is a provider workspace package whose
 *   kind is `protocol`, by a `link:` to its directory, whose manifest names that dependency.
 * - S2: a source names its own package's files (by their real paths) and its dependencies alone,
 *   no subpath of one, and in shipped code no triple-slash type or lib reference; a test names
 *   `vitest`, Node's builtins and Node's types besides. A package holds no symlink.
 * - S3: the sdk's pnpm pin and supply settings are the provider's: every top-level setting of the
 *   provider's pnpm-workspace.yaml but its packages, the same, a block of entries holding a subset.
 */
export function sdkViolations(root: string): Finding[] {
	const findings: Finding[] = [];
	const repo = resolve(root, "..");
	const place = (path: string) => relative(root, path);
	const provider = providerPackages(repo);

	const sdkManifest = readManifest(root);
	if (sdkManifest?.packageManager !== readManifest(repo)?.packageManager)
		findings.push({ id: "S3", place: "package.json", what: "pins another pnpm than the provider" });
	const theirs = settingsOf(readFileSync(join(repo, "pnpm-workspace.yaml"), "utf8"));
	const ours = settingsOf(readFileSync(join(root, "pnpm-workspace.yaml"), "utf8"));
	for (const [key, value] of theirs) {
		if (key === "packages") continue;
		const mine = ours.get(key);
		const same =
			typeof value === "string"
				? mine === value
				: mine instanceof Map && [...mine].every(([k, v]) => value.get(k) === v);
		if (!same)
			findings.push({
				id: "S3",
				place: "pnpm-workspace.yaml",
				what: `${key} differs from the provider's`,
			});
	}

	const packagesDir = join(root, "packages");
	for (const entry of existsSync(packagesDir) ? readdirSync(packagesDir) : []) {
		const dir = join(packagesDir, entry);
		const manifest = readManifest(dir);
		if (!manifest) continue;
		const declared = new Set<string>();
		for (const field of dependencyFields) {
			const deps = (manifest[field] ?? {}) as Record<string, string>;
			for (const [name, spec] of Object.entries(deps)) {
				declared.add(name);
				const target = spec.startsWith("link:") ? real(resolve(dir, spec.slice(5))) : undefined;
				const linked = target === undefined ? undefined : provider.get(target);
				if (linked?.name !== name || linked.kind !== "protocol")
					findings.push({
						id: "S1",
						place: place(join(dir, "package.json")),
						what: `${field} names ${name} (${spec}), no protocol package of the provider`,
					});
			}
		}
		const { files, links } = walk(dir);
		for (const link of links) findings.push({ id: "S2", place: place(link), what: "is a symlink" });
		const realDir = real(dir);
		const own = (from: string, specifier: string) =>
			inside(realDir, real(resolve(dirname(from), specifier)));
		for (const path of files.filter((file) => sourceFile.test(file))) {
			const test = isTest(relative(dir, path));
			const refs = referencesOf(readFileSync(path, "utf8"));
			const refused = [
				...refs.modules.filter((specifier) =>
					specifier.startsWith(".")
						? !own(path, specifier)
						: !(
								declared.has(specifier) ||
								(test && (specifier === "vitest" || specifier.startsWith("node:")))
							),
				),
				...refs.paths.filter((specifier) => !own(path, specifier)),
				...refs.types.filter((name) => !(test && name === "node")),
				...refs.libs.filter(() => !test),
			];
			for (const specifier of refused)
				findings.push({ id: "S2", place: place(path), what: `imports ${specifier}` });
		}
	}
	return findings;
}
