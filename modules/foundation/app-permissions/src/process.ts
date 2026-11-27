/** What one process of an app may do, in no runtime's words: as `permissions.json` holds it, one per process. */
import { type Permissions, permissionsProblems } from "./declaration.ts";

/** One package the process composes that declares what it does beyond its code. */
export interface Declared {
	readonly package: string;
	/** The section of the configuration its keys are under. */
	readonly section: string;
	readonly permissions: Permissions;
	/** Whether it starts a process (its manifest's `forks`). */
	readonly forks: boolean;
}

export interface ProcessPermissions {
	/** Directories its code is read from: the app, the packages it is made of, the package store. */
	readonly code: readonly string[];
	readonly declared: readonly Declared[];
	/** Whether a package it composes reaches the network. */
	readonly network: boolean;
}

/** An app's processes, by the script that starts each (`start` among them). */
export interface AppPermissions {
	readonly v: 1;
	readonly processes: Readonly<Record<string, ProcessPermissions>>;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
const strings = (value: unknown) =>
	Array.isArray(value) && value.every((s) => typeof s === "string");

/** The app's permissions read from `permissions.json`'s text, or why not, each problem named. */
export function appPermissionsOf(
	text: string,
): { readonly permissions: AppPermissions } | { readonly problems: readonly string[] } {
	let value: unknown;
	try {
		value = JSON.parse(text);
	} catch {
		return { problems: ["permissions.json is no JSON"] };
	}
	if (!isObject(value) || value.v !== 1 || !isObject(value.processes))
		return { problems: ["permissions.json is version 1 with its processes"] };
	const problems: string[] = [];
	for (const [name, process] of Object.entries(value.processes)) {
		if (!isObject(process)) {
			problems.push(`${name} is an object`);
			continue;
		}
		if (!strings(process.code) || (process.code as string[]).some((root) => !root.startsWith("/")))
			problems.push(`${name}.code is a list of absolute directories`);
		if (typeof process.network !== "boolean") problems.push(`${name}.network is true or false`);
		if (!Array.isArray(process.declared)) {
			problems.push(`${name}.declared is a list`);
			continue;
		}
		for (const [i, item] of (process.declared as unknown[]).entries()) {
			const at = `${name}.declared[${i}]`;
			if (!isObject(item) || typeof item.package !== "string" || typeof item.section !== "string") {
				problems.push(`${at} names its package and section`);
				continue;
			}
			if (typeof item.forks !== "boolean") problems.push(`${at}.forks is true or false`);
			for (const problem of permissionsProblems(item.permissions))
				problems.push(`${at}: ${problem}`);
		}
	}
	return problems.length > 0 ? { problems } : { permissions: value as unknown as AppPermissions };
}
