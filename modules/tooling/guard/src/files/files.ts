/** G35: product and companion code that touches files declares what it reads and writes (`permissions`). */
import { permissionsProblems } from "@mod/app-permissions";
import type { Edge, FileFacts, Pkg } from "@mod/guard-imports";
import { networkKinds } from "../kinds.ts";
import { budgetsAsTest, type Scope } from "../units.ts";

/** Node's file system modules, by any of their names. */
const fileModules = ["node:fs", "node:fs/promises"];
const nodeName = (specifier: string) =>
	specifier.startsWith("node:") ? specifier : `node:${specifier}`;

/** Whether an edge loads a file system module as a value: imported or re-exported (not as a type alone), or loaded. */
const loadsFiles = (edge: Edge) => {
	if (!edge.loads) return false;
	const specifier = edge.specifier.text;
	if (specifier === undefined || !fileModules.includes(nodeName(specifier))) return false;
	if (edge.form !== "import" && edge.form !== "export-from") return true;
	return edge.bindings.length === 0 || edge.bindings.some((binding) => !binding.typeOnly);
};

/** Whether a file's facts load a file system module. */
export const touchesFiles = (facts: FileFacts) => facts.edges.some(loadsFiles);

/** G35: a product package or companion whose shipped code loads `node:fs` declares `permissions`, one `app-permissions` takes. */
export function filesRules(s: Scope, p: Pkg) {
	if (!networkKinds.includes(s.kindOf(p))) return;
	const rule = "G35 code touching files declares its permissions";
	const declared = p.manifest.permissions;
	if (declared !== undefined) {
		for (const problem of permissionsProblems(declared)) s.report(rule, p.name, problem);
		return;
	}
	for (const file of s.sources(p)) {
		if (s.isTest(file) || budgetsAsTest(s, p, file)) continue;
		if (touchesFiles(s.factsOf(p, file)))
			s.report(rule, `${p.name}/${file}`, "node:fs (no permissions declared)");
	}
}
