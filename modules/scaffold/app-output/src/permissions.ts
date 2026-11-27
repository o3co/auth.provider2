/** The app's processes' permissions (`permissions.json`), from what the packages each composes declare. */
import {
	atKeyPath,
	type Declared,
	type Permissions,
	permissionsProblems,
} from "@mod/app-permissions";
import { type Fragment, fragmentsIn } from "./fragments.ts";

/** A package a process composes, as the caller read it. */
interface Composed {
	readonly name: string;
	readonly dir: string;
	readonly manifest: Readonly<Record<string, unknown>>;
}

/** Whether a key path names a key of a fragment's section, by `app-permissions`' reading of a key path. */
export const inFragment = (tree: unknown, path: string) => atKeyPath(tree, path).length > 0;

/**
 * What each composed package declares, with its section: refused, naming the package, where its
 * `permissions` is no declaration `app-permissions` takes, a file key is no key of its fragment
 * (`config.example`), or it names `child` with no `forks`. A package that forks and declares nothing
 * is declared as forking always.
 */
export async function declaredOf(composed: readonly Composed[]): Promise<Declared[]> {
	const declared: Declared[] = [];
	for (const p of composed) {
		const forks = p.manifest.forks !== undefined;
		if (p.manifest.permissions === undefined && !forks) continue;
		const permissions = (p.manifest.permissions ?? {}) as Permissions;
		const problems = permissionsProblems(permissions);
		if (problems.length > 0) throw new Error(`${p.name}: ${problems.join("; ")}`);
		if (permissions.child !== undefined && !forks)
			throw new Error(`${p.name}: permissions names child, but it has no forks`);
		const [fragment] = (await fragmentsIn([p.dir])) as (Fragment | undefined)[];
		const keys = [
			...(permissions.read?.keys ?? []),
			...(permissions.write?.keys ?? []),
			...(permissions.write?.beside ?? []),
		];
		for (const key of keys)
			if (!fragment || !inFragment(fragment.tree, key))
				throw new Error(
					`${p.name}: permissions names ${key}, which its config.example does not hold`,
				);
		if (permissions.child !== undefined && !fragment)
			throw new Error(`${p.name}: permissions names child, but it has no config.example`);
		// A declaration of nothing, by a package that forks nothing, grants nothing: left out.
		const empty = Object.keys(permissions).length === 0;
		if (!empty || forks)
			declared.push({ package: p.name, section: fragment?.section ?? "", permissions, forks });
	}
	return declared;
}

/** `permissions.json`: the app's start process, its code roots, what it composes declares, and whether it reaches the network. */
export const permissionsJson = (start: {
	readonly code: readonly string[];
	readonly declared: readonly Declared[];
	readonly network: boolean;
}) => `${JSON.stringify({ v: 1, processes: { start } }, null, "\t")}\n`;
