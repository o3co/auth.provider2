/** A package's `permissions`: what it reads and writes beyond its code, and whether it starts a process. */

/** A literal path a package reads, and whether it is a file or a directory listed. */
export interface PathRead {
	readonly path: string;
	readonly kind: "file" | "dir";
}

/** A file a variable names, and the library's own default where the variable is unset (`~/` the home directory). */
export interface EnvRead {
	readonly name: string;
	readonly default?: string;
	/** Whether its reader takes a leading `~/` in the variable's value as the home directory, as it does in the default. */
	readonly home?: boolean;
}

/** Where a package's child processes are granted: its section's key set to the value; an unset key does not hold. */
export interface ChildCondition {
	readonly key: string;
	readonly is: string;
}

export interface Permissions {
	readonly read?: {
		/** Key paths of the package's own section naming files it reads; `*` is each element of a list. */
		readonly keys?: readonly string[];
		readonly paths?: readonly PathRead[];
		readonly env?: readonly EnvRead[];
	};
	readonly write?: {
		/** Key paths of its own section naming files it writes. */
		readonly keys?: readonly string[];
		/** Key paths naming a file whose whole directory it reads and writes (a lock and its temporary siblings, the directory's sync). */
		readonly beside?: readonly string[];
	};
	/** Where its `forks` start a process: always where absent, else where `when` holds. */
	readonly child?: { readonly when: ChildCondition };
}

/** A key path: lowercase words joined by `.`, `*` a whole word for each element of a list, never first. */
const keyPath = /^[a-z0-9][a-z0-9-]*(\.([a-z0-9][a-z0-9-]*|\*))*$/;
/** A condition's key: as a key path, with no `*`. */
const plainKey = /^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$/;
const envName = /^[A-Z_][A-Z0-9_]*$/;

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** Why a value is no `Permissions`, each problem named; none where it is one. An empty object is one: code alone. */
export function permissionsProblems(value: unknown): string[] {
	const problems: string[] = [];
	if (!isObject(value)) return ["permissions is an object"];
	const only = (at: string, object: Record<string, unknown>, members: readonly string[]) => {
		for (const name of Object.keys(object))
			if (!members.includes(name)) problems.push(`${at}.${name} is no member`);
	};
	const list = (at: string, items: unknown, each: (item: unknown, at: string) => void) => {
		if (items === undefined) return;
		if (!Array.isArray(items)) return problems.push(`${at} is a list`);
		for (const [i, item] of items.entries()) each(item, `${at}[${i}]`);
	};
	const keys = (at: string, items: unknown) =>
		list(at, items, (item, here) => {
			if (typeof item !== "string" || !keyPath.test(item)) problems.push(`${here} is no key path`);
		});
	only("permissions", value, ["read", "write", "child"]);
	const { read, write, child } = value;
	if (read !== undefined) {
		if (!isObject(read)) problems.push("permissions.read is an object");
		else {
			only("permissions.read", read, ["keys", "paths", "env"]);
			keys("permissions.read.keys", read.keys);
			list("permissions.read.paths", read.paths, (item, here) => {
				if (!isObject(item)) return problems.push(`${here} is an object`);
				only(here, item, ["path", "kind"]);
				if (typeof item.path !== "string" || !item.path.startsWith("/"))
					problems.push(`${here}.path is an absolute path`);
				if (item.kind !== "file" && item.kind !== "dir")
					problems.push(`${here}.kind is file or dir`);
			});
			list("permissions.read.env", read.env, (item, here) => {
				if (!isObject(item)) return problems.push(`${here} is an object`);
				only(here, item, ["name", "default", "home"]);
				if (item.home !== undefined && typeof item.home !== "boolean")
					problems.push(`${here}.home is true or false`);
				if (typeof item.name !== "string" || !envName.test(item.name))
					problems.push(`${here}.name is a variable's name`);
				if (item.default !== undefined && typeof item.default !== "string")
					problems.push(`${here}.default is a path`);
			});
		}
	}
	if (write !== undefined) {
		if (!isObject(write)) problems.push("permissions.write is an object");
		else {
			only("permissions.write", write, ["keys", "beside"]);
			keys("permissions.write.keys", write.keys);
			keys("permissions.write.beside", write.beside);
		}
	}
	if (child !== undefined) {
		if (!isObject(child) || !isObject(child.when)) problems.push("permissions.child names when");
		else {
			only("permissions.child", child, ["when"]);
			only("permissions.child.when", child.when, ["key", "is"]);
			if (typeof child.when.key !== "string" || !plainKey.test(child.when.key))
				problems.push("permissions.child.when.key is a key of the section");
			if (typeof child.when.is !== "string") problems.push("permissions.child.when.is is a value");
		}
	}
	return problems;
}
