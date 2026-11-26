/** Each module's section's defaults as `reference.conf`, from its schema: one file beside each package's manifest, for an operator to read. */
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { Pkg } from "@mod/guard-imports";

/** A section's schema, as the kernel takes one: a Standard Schema that writes its JSON Schema. */
interface Schema {
	readonly "~standard": {
		readonly jsonSchema?: { readonly input: (options: { readonly target: string }) => unknown };
	};
}

/** The part of a JSON Schema the reference reads. */
export interface JsonSchema {
	readonly type?: string | readonly string[];
	readonly properties?: Readonly<Record<string, JsonSchema>>;
	readonly required?: readonly string[];
	readonly items?: JsonSchema;
	readonly enum?: readonly unknown[];
	readonly anyOf?: readonly JsonSchema[];
	readonly oneOf?: readonly JsonSchema[];
	readonly const?: unknown;
	readonly default?: unknown;
	readonly description?: string;
	readonly minimum?: number;
	readonly maximum?: number;
}

/** One key of a section, as the reference shows it. */
export interface Row {
	readonly key: string;
	readonly type: string;
	readonly default?: unknown;
	/** With `within`, required once that object is set. */
	readonly required: boolean;
	/** The optional object the key lies in, nearest first: its default and requiredness hold only once that is set. */
	readonly within?: string;
	/** The variants the row holds in, outermost first: a key's own facts that differ by variant are one row each. */
	readonly when?: readonly Clause[];
	readonly description?: string;
}

/** One variant clause: the key that tells a union's variants apart, and the values it takes in them. */
export interface Clause {
	readonly key: string;
	readonly values: readonly string[];
}

const typeOf = (s: JsonSchema): string => {
	if (s.const !== undefined) return String(s.const);
	if (s.enum) return s.enum.map((v) => String(v)).join(" | ");
	const either = s.anyOf ?? s.oneOf;
	if (either) return [...new Set(either.map(typeOf))].join(" | ");
	if (s.type === "array") return `list of ${s.items ? typeOf(s.items) : "any"}`;
	if (s.type === "object") return "map";
	const name = Array.isArray(s.type) ? s.type.join(" | ") : (s.type ?? "any");
	const range =
		s.minimum !== undefined || s.maximum !== undefined
			? ` (${s.minimum ?? ""}–${s.maximum ?? ""})`
			: "";
	return `${name}${range}`;
};

/** An object's keys, or a union of objects' keys merged: required only where every variant requires it. */
function objectOf(s: JsonSchema): JsonSchema | undefined {
	if (s.properties) return s;
	const variants = (s.oneOf ?? s.anyOf ?? []).map(objectOf);
	if (variants.length === 0 || variants.some((v) => v === undefined)) return undefined;
	const properties: Record<string, JsonSchema> = {};
	for (const v of variants as JsonSchema[]) {
		for (const [name, p] of Object.entries(v.properties ?? {})) {
			const held = properties[name];
			const either = held ? [...(held.anyOf ?? [held]), p] : undefined;
			properties[name] = either
				? {
						anyOf: either,
						...(held?.default !== undefined ? { default: held.default } : {}),
						...(held?.description ? { description: held.description } : {}),
					}
				: p;
		}
	}
	const required = Object.keys(properties).filter((name) =>
		(variants as JsonSchema[]).every((v) => (v.required ?? []).includes(name)),
	);
	return { type: "object", properties, required };
}

/** A union's object variants, nested unions flattened; none where one of them is not an object. */
function variantsOf(s: JsonSchema): JsonSchema[] | undefined {
	if (s.properties) return [s];
	const either = s.oneOf ?? s.anyOf;
	if (!either) return undefined;
	const all = either.map(variantsOf);
	return all.some((v) => v === undefined) ? undefined : (all as JsonSchema[][]).flat();
}

/** The values a variant names for `name`, as a constant or a list of them. */
function valuesAt(v: JsonSchema, name: string): string[] | undefined {
	const p = v.properties?.[name];
	if (p?.const !== undefined) return [String(p.const)];
	return p?.enum?.map((value) => String(value));
}

/** The key that tells a union's variants apart: each names its own values of it, none another's. */
function discriminatorOf(variants: readonly JsonSchema[]): string | undefined {
	if (variants.length < 2) return undefined;
	return Object.keys(variants[0]?.properties ?? {}).find((name) => {
		const values = variants.map((v) => valuesAt(v, name));
		if (values.some((v) => v === undefined)) return false;
		const all = (values as string[][]).flat();
		return new Set(all).size === all.length;
	});
}

/**
 * Each key of a schema, objects with properties walked into. A key inside an object neither required nor defaulted lies `within` it: its default and
 * requiredness hold once that object is set. Inside a defaulted object no key is required. In a
 * union told apart by one key, a key holds `when` that key takes the values of the variants it is
 * alike in; where all of them are alike, it holds in each.
 */
export function rowsOf(
	schema: JsonSchema,
	path: readonly string[],
	held = true,
	within?: string,
	when: readonly Clause[] = [],
): Row[] {
	const variants = variantsOf(schema);
	const on = variants === undefined ? undefined : discriminatorOf(variants);
	if (variants === undefined || on === undefined) {
		const object = objectOf(schema);
		return Object.entries(object?.properties ?? {}).flatMap(([name, s]) =>
			keyRows(name, s, (object?.required ?? []).includes(name), path, held, within, when),
		);
	}
	const by = [...path, on].join(".");
	const names = [...new Set(variants.flatMap((v) => Object.keys(v.properties ?? {})))];
	return names.flatMap((name) => {
		const holding = variants.filter((v) => v.properties?.[name] !== undefined);
		if (name === on) {
			const each = holding.map((v) => v.properties?.[name] as JsonSchema);
			const described = each.find((p) => p.description)?.description;
			const either = { anyOf: each, ...(described ? { description: described } : {}) };
			return keyRows(name, either, true, path, held, within, when);
		}
		// The variants alike in this key, its schema the same and required in each or in none.
		const alike = Map.groupBy(holding, (v) =>
			JSON.stringify([v.properties?.[name], (v.required ?? []).includes(name)]),
		);
		const everywhere = alike.size === 1 && holding.length === variants.length;
		return [...alike.values()].flatMap((group) => {
			const [v] = group as [JsonSchema];
			const clause = { key: by, values: group.flatMap((g) => valuesAt(g, on) ?? []) };
			return keyRows(
				name,
				v.properties?.[name] as JsonSchema,
				(v.required ?? []).includes(name),
				path,
				held,
				within,
				everywhere ? when : [...when, clause],
			);
		});
	});
}

/** One key's rows: an object's walked into, a leaf's its own. */
function keyRows(
	name: string,
	s: JsonSchema,
	listed: boolean,
	path: readonly string[],
	held: boolean,
	within: string | undefined,
	when: readonly Clause[],
): Row[] {
	const keyPath = [...path, name];
	const own = listed && s.default === undefined;
	if (variantsOf(s)) {
		if (own || s.default !== undefined) return rowsOf(s, keyPath, held && own, within, when);
		return rowsOf(s, keyPath, true, keyPath.join("."), when);
	}
	const key = keyPath.join(".");
	return [
		{
			key,
			type: typeOf(s),
			...(s.default === undefined ? {} : { default: s.default }),
			required: held && own,
			...(within === undefined ? {} : { within }),
			...(when.length === 0 ? {} : { when }),
			...(s.description ? { description: s.description } : {}),
		},
	];
}

/** A nested object that says what it is: its key and its own description, shown before its keys. */
export interface Described {
	readonly key: string;
	readonly description: string;
}

/** Each nested object of a schema with a description of its own, outermost first, as `rowsOf` walks into it. */
export function describedOf(schema: JsonSchema, path: readonly string[]): Described[] {
	const object = objectOf(schema);
	return Object.entries(object?.properties ?? {}).flatMap(([name, s]) => {
		if (objectOf(s) === undefined) return [];
		const key = [...path, name].join(".");
		const own = s.description ? [{ key, description: s.description }] : [];
		return [...own, ...describedOf(s, [...path, name])];
	});
}

/** Each row, after the described objects it lies in that no earlier row did: an object before its first key. */
function withObjects<T>(
	rows: readonly Row[],
	objects: readonly Described[],
	row: (r: Row) => T[],
	object: (o: Described) => T[],
): T[] {
	const shown = new Set<string>();
	return rows.flatMap((r) => {
		const before = objects.filter((o) => !shown.has(o.key) && r.key.startsWith(`${o.key}.`));
		for (const o of before) shown.add(o.key);
		return [...before.flatMap(object), ...row(r)];
	});
}

/** A section of the workspace: its name, its owner, the owner's directory, its rows and its described objects. */
export interface Section {
	readonly section: string;
	readonly owner: string;
	readonly dir: string;
	readonly rows: Row[];
	/** Its nested objects that say what they are, each shown before its keys. */
	readonly objects?: readonly Described[];
}

const sectionOf = (schema: Schema, section: string, owner: string, dir: string) => {
	const read = schema["~standard"].jsonSchema?.input({ target: "draft-2020-12" }) as
		| JsonSchema
		| undefined;
	if (!read) return undefined;
	const rows = rowsOf(read, [section]);
	return { section, owner, dir, rows, objects: describedOf(read, [section]) };
};

/** Every section of the workspace: each module's, by its `./module` export, and the kernel's, by its contract. */
export async function sectionsIn(packages: readonly Pkg[]): Promise<Section[]> {
	const found: Section[] = [];
	for (const { name, dir, manifest } of packages) {
		const exports = manifest.exports as Readonly<Record<string, string>> | undefined;
		const entry = exports?.["./module"];
		if (entry) {
			const module = (await import(pathToFileURL(join(dir, entry)).href)).default as {
				name: string;
				section?: Schema;
			};
			const read = module.section && sectionOf(module.section, module.name, name, dir);
			if (read) found.push(read);
		} else if (name === "@mod/kernel" && exports?.["."]) {
			// The kernel reads its own section, by the schema its contract exports.
			const own = (await import(pathToFileURL(join(dir, exports["."])).href))
				.kernelSection as Schema;
			const read = sectionOf(own, "kernel", name, dir);
			if (read) found.push(read);
		}
	}
	return found.sort((a, b) => (a.section < b.section ? -1 : 1));
}

/** Values in prose: `a`, `a or b`, `a, b or c`. */
const either = (values: readonly string[]) =>
	values.length < 2 ? (values[0] ?? "") : `${values.slice(0, -1).join(", ")} or ${values.at(-1)}`;

/** What a row holds under, outermost first: the optional object it lies within set, each variant it holds in. */
const conditionsOf = (r: Row, write: (text: string, kind: "key" | "value") => string) => {
	const set = r.within === undefined ? [] : [{ key: r.within, values: undefined }];
	// By the object each is of, the variant of an object before an optional object in it.
	const level = (c: { key: string; values: unknown }) =>
		2 * c.key.split(".").length + (c.values === undefined ? 1 : 0);
	const all = [...set, ...(r.when ?? [])].sort((a, b) => level(a) - level(b));
	const said = all.map(({ key, values }) =>
		values === undefined
			? `${write(key, "key")} is set`
			: `${write(key, "key")} is ${either(values.map((v) => write(v, "value")))}`,
	);
	return said.length === 0 ? "" : `when ${said.join(" and ")}`;
};

/** A key as HOCON writes it: quoted when it holds more than letters, digits, `-` and `_`. */
const hoconKey = (key: string) => (/^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key));

/** A value as HOCON writes it: a number with its unit bare (`5m`, `64KiB`), anything else as JSON. */
const hoconValue = (value: unknown) =>
	typeof value === "string" && /^\d+(\.\d+)?\s?[A-Za-z]+$/.test(value)
		? value
		: JSON.stringify(value);

/**
 * A section's defaults as HOCON, for an operator to read: each key, described, with its default or
 * what it needs; a key within an optional object or held in some variants only as a comment, saying when it holds.
 */
export function referenceConfOf({
	section,
	owner,
	rows,
	objects = [],
}: Omit<Section, "dir">): string {
	const inSection = (path: string) => path.split(".").slice(1).map(hoconKey).join(".");
	const described = (o: Described) =>
		o.description
			.split("\n")
			.filter(Boolean)
			.map((line, i) => (i === 0 ? `\t# ${inSection(o.key)}: ${line}` : `\t# ${line}`));
	const keys = withObjects(
		rows,
		objects,
		(r) => {
			const key = inSection(r.key);
			const about = (r.description ?? "")
				.split("\n")
				.filter(Boolean)
				.map((line) => `\t# ${line}`);
			const needs = r.required ? "required" : "optional";
			const once = conditionsOf(r, (text, kind) => (kind === "key" ? inSection(text) : text));
			if (once !== "") {
				const value =
					r.default !== undefined
						? `\t# ${key} = ${hoconValue(r.default)} (${once})`
						: `\t# ${key}: ${needs} ${once}`;
				return [...about, value];
			}
			const value =
				r.default !== undefined ? `\t${key} = ${hoconValue(r.default)}` : `\t# ${key}: ${needs}`;
			return [...about, value];
		},
		described,
	);
	return [
		`# The defaults of \`${owner}\`'s section, generated by \`references\` from its schema: do not edit; run \`pnpm --filter @mod/references run configuration\`.`,
		"# For reading only: the module applies these itself, and the app does not load this file.",
		`${hoconKey(section)} {`,
		...keys,
		"}",
		"",
	].join("\n");
}

/** Where a section's defaults lie: beside its package's manifest. */
export const referenceConfFile = (dir: string) => join(dir, "reference.conf");
