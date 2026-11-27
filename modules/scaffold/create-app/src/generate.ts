/** A generated app from a pattern: the selection composed, what it reaches, and the files app-output writes. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Known, writeApp } from "@mod/app-output";
import { composed, reached, type Selection } from "@mod/combinations";
import { workspacePackages } from "@mod/workspace-packages";
import { type Pattern, patternNamed } from "./patterns.ts";

/** What the operator asks: a pattern, and what is added or chosen beside it. */
export interface Plan {
	readonly pattern: string;
	readonly add?: readonly string[];
	readonly axes?: Readonly<Record<string, string>>;
}

/** The workspace this package lies in. */
const root = join(import.meta.dirname, "..", "..", "..", "..");
let read: Map<string, Known> | undefined;
const workspace = () => {
	read ??= new Map(
		workspacePackages(root).map((p) => [
			p.name,
			{
				name: p.name,
				dir: p.dir,
				manifest: JSON.parse(readFileSync(join(p.dir, "package.json"), "utf8")),
			},
		]),
	);
	return read;
};

/** A pattern's selection, with what the plan adds and chooses beside it. */
export function selectionOf(pattern: Pattern, plan: Omit<Plan, "pattern"> = {}): Selection {
	return {
		features: { [pattern.name]: pattern.features },
		axes: { ...pattern.axes, ...plan.axes },
		add: [...pattern.add, ...(plan.add ?? [])],
	};
}

/** The pattern a plan names; refuses one that is no pattern. */
export function patternOf(plan: Plan): Pattern {
	const pattern = patternNamed(plan.pattern);
	if (!pattern) throw new Error(`${plan.pattern}: not a pattern`);
	return pattern;
}

/** Each line of a composed adapter that declares itself never a default: its own `asks`, the claim it does not hold. */
export function noticesOf(selection: Selection): string[] {
	return composed(selection).flatMap((name) => {
		const manifest = workspace().get(name)?.manifest;
		if (manifest?.neverDefault !== true) return [];
		const asks = (manifest.asks ?? []) as readonly (string | { readonly line: string })[];
		return asks.map((ask) => `notice: ${name}: ${typeof ask === "string" ? ask : ask.line}`);
	});
}

/** Writes the app the plan names into a missing or empty target; answers the notices to tell. */
export async function generate(target: string, plan: Plan): Promise<string[]> {
	const pattern = patternOf(plan);
	const selection = selectionOf(pattern, plan);
	await writeApp(target, {
		modules: composed(selection),
		reached: reached(selection),
		companions: pattern.companions,
		required: pattern.required,
		known: (name) => workspace().get(name),
		dependency: (known) => `link:${known.dir}`,
		guide: { title: pattern.name, use: pattern.use, card: pattern.card },
	});
	return noticesOf(selection);
}
