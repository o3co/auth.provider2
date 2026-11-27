import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { type Pkg, readWorkspace } from "@mod/guard-imports";

export interface Doc {
	readonly path: string;
	readonly text: string;
}

function walk(dir: string, base = dir): string[] {
	return readdirSync(dir).flatMap((entry) => {
		if (entry === "node_modules" || entry.startsWith(".")) return [];
		const path = join(dir, entry);
		return statSync(path).isDirectory() ? walk(path, base) : [relative(base, path)];
	});
}

/** Every Markdown document in the repository, without node_modules. */
export function readDocuments(root: string): Doc[] {
	return walk(root)
		.filter((file) => file.endsWith(".md"))
		.map((file) => ({ path: join(root, file), text: readFileSync(join(root, file), "utf8") }));
}

/** The sdk's packages: its workspace's under its own `packages`, by real path; none there refuses. */
export function readSdkPackages(root: string): Pkg[] {
	const sdk = join(root, "sdk");
	if (!existsSync(join(sdk, "pnpm-workspace.yaml")))
		throw new Error(`guard: no sdk workspace at ${sdk} (its pnpm-workspace.yaml)`);
	const dir = join(sdk, "packages");
	if (!existsSync(dir)) throw new Error(`guard: no sdk package under ${dir}`);
	const under = `${realpathSync(dir)}${sep}`;
	const packages = readWorkspace(sdk).filter((p) => `${p.dir}${sep}`.startsWith(under));
	if (packages.length === 0) throw new Error(`guard: no sdk package under ${under}`);
	return packages;
}
