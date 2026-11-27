/**
 * A run's report: its results as tables, in the ledger's keys and words. It reads `results`' judgment,
 * whose files are tests', so its files are tests' too.
 */
import type { Deviation } from "../../deviations/deviations.ts";
import type { Class, Judged, MetCondition, RunRefusal } from "../../results/test/results.ts";
import type { Reading, Word } from "../../words/words.ts";
import { wordName, words } from "../../words/words.ts";

/** What a report is written from: the run's name, plan and suite pin, the scene's differences from the pattern, the run judged, the ledger. */
export interface ReportInput {
	readonly run: keyof typeof cannotShow;
	readonly plan: string;
	readonly pin: string;
	readonly differences: readonly string[];
	readonly judged: {
		readonly modules: readonly Judged[];
		readonly problems: readonly string[];
		readonly passed: boolean;
	};
	readonly ledger: readonly Deviation[];
}

/** What each run gives no evidence of, so that no reader takes its passes for more. */
export const cannotShow = {
	A: "Run A gives no evidence of the token endpoint, the resource, DPoP past PAR, or refresh: its expected results have every flow module stop at the wall, before a token is issued. That is run B's (the JAR and form_post adaptation, internal).",
} as const;

const classes: readonly Class[] = [
	"crossed",
	"before-wall",
	"explained",
	"unconfirmed",
	"skipped",
	"failed",
];

const notes = [
	"A module's class: `crossed`, passed to its end or refused on the condition it tests; `before-wall`, passed but refused on another cause a ledger row names, no evidence; `explained`, each condition by a key a refusal of its own block shows observed; `unconfirmed`, words the table cannot tell apart, failing no run; `skipped`, by the suite; `failed`, failing the run.",
	"A refusal's observed key is the one ledger row whose words alone it is (the word table); only an observed key explains (decision 12). A computed key is a row the product's own rules find a module's pushed JARs break, shown beside and never compared.",
	"A refusal's reading is its own: a block may read unconfirmed though its module is explained. A module's `Unconfirmed` lists the refusals no entry names; `no row` is a refusal no row's words fit (the condition the module tests, or the Front's fixed answer).",
	"An empty text in a JAR is a value, judged by its item's rule (sdk-core-wire's `itemsFromJar`); a null is as if left out, but `request`'s and `request_uri`'s.",
	"A review's verdict is the harness's own record: the suite's API gives a REVIEW none.",
	"A refusal at the resource is the harness's resource role's, not the provider's.",
];

/** A text on one line, whatever its line ends. */
const line = (text: string) => text.replace(/\r\n|\r|\n/g, " ");
/** A cell: one line, a `|` escaped, no markup of HTML. */
const cell = (text: string) => line(text).replace(/</g, "&lt;").replace(/\|/g, "\\|");
const code = (texts: readonly string[]) => texts.map((t) => `\`${t}\``).join(", ") || "—";
const row = (cells: readonly string[]) => `| ${cells.map(cell).join(" | ")} |`;
const table = (head: readonly string[], rows: readonly (readonly string[])[]) => [
	row(head),
	`|${head.map(() => "---|").join("")}`,
	...rows.map(row),
];

const readingText = (reading: Reading) =>
	reading.kind === "observed"
		? `observed \`${reading.key}\``
		: reading.kind === "unconfirmed"
			? `unconfirmed (${reading.keys.length > 0 ? code(reading.keys) : "many causes"})`
			: "no row";
const wordsText = (r: RunRefusal) =>
	[r.error, r.description].filter((t) => t !== undefined).join(": ") || "no words";
const conditionText = (c: MetCondition) =>
	!c.named
		? "no entry names it"
		: c.keys.length === 0
			? "named, by no key"
			: `by ${code(c.keys)}${c.unshown.length > 0 ? `; its block shows not ${code(c.unshown)}` : ""}`;

/** A module's refusals and conditions, block by block in the log's order (outside every block last), each refusal before its block's conditions. */
function blockRows(m: Judged, variant: string): string[][] {
	const at = (blockId: string) => {
		const i = m.blocks.findIndex((b) => b.id === blockId);
		return i < 0 ? m.blocks.length : i;
	};
	const where = (blockId: string) => {
		const b = m.blocks.find((x) => x.id === blockId);
		return b === undefined ? ["no block", "—"] : [b.message, b.id];
	};
	const refused = m.refusals.map((r) => ({
		at: at(r.blockId),
		cells: [
			...where(r.blockId),
			"—",
			r.refuser,
			r.place,
			String(r.status),
			wordsText(r),
			readingText(r.reading),
		],
	}));
	const conditioned = m.conditions.map((c) => ({
		at: at(c.blockId),
		cells: [...where(c.blockId), `${c.kind} ${c.src}`, "—", "—", "—", "—", conditionText(c)],
	}));
	return [...refused, ...conditioned]
		.sort((a, b) => a.at - b.at)
		.map((x) => [m.test, variant, ...x.cells]);
}

/** How a run names each key: observed, computed, unconfirmed, by a condition's entry. */
function namedAs(modules: readonly Judged[]): Map<string, Set<string>> {
	const named = new Map<string, Set<string>>();
	const add = (how: string) => (key: string) =>
		named.set(key, (named.get(key) ?? new Set()).add(how));
	for (const m of modules) {
		m.observed.forEach(add("observed"));
		m.computed.forEach(add("computed"));
		for (const r of m.refusals)
			if (r.reading.kind === "unconfirmed") r.reading.keys.forEach(add("unconfirmed"));
		for (const c of m.conditions) c.keys.forEach(add("a condition's"));
	}
	return named;
}
const hows = ["observed", "computed", "unconfirmed", "a condition's"];

/** What tells a word from another of its row's in the same words, where something does. */
const toldBy = (w: Word) =>
	[
		w.dpopHeader === undefined ? [] : [w.dpopHeader ? "with a DPoP header" : "with no DPoP header"],
		w.startedBefore === undefined
			? []
			: [w.startedBefore ? "its request_uri started before" : "its request_uri new"],
	]
		.flat()
		.join(", ");

/** The report as Markdown: the head, how to read it, and four tables joined by test, variant and key. */
export function reportOf(input: ReportInput): string {
	const { modules, problems, passed } = input.judged;
	const variantOf = (v: Readonly<Record<string, string>>) =>
		JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))));
	const variants = [...new Set(modules.map((m) => variantOf(m.variant)))];
	const label = (v: Readonly<Record<string, string>>) => `v${variants.indexOf(variantOf(v)) + 1}`;
	const count = (c: Class) => `${c} ${modules.filter((m) => m.class === c).length}`;
	const named = namedAs(modules);
	const howOf = (key: string) => hows.filter((h) => named.get(key)?.has(h)).join(", ");
	const inLedger = new Set(input.ledger.map((d) => d.key));
	const computed = [...new Set(modules.flatMap((m) => m.computed))].sort();
	const backing = computed.flatMap((key) => {
		const its = words.filter((w) => w.key === key);
		return its.length === 0
			? [[`\`${key}\``, "none: no refusal shows it", "—"]]
			: its.map((w) => [
					`\`${key}\``,
					wordName(w),
					`${w.refuser} at ${w.place}: ${w.error}: ${w.description}${toldBy(w) === "" ? "" : ` (${toldBy(w)})`}`,
				]);
	});
	return `${[
		`# OIDF conformance, run ${input.run}`,
		"",
		`- Plan: \`${input.plan}\`, the suite at \`${input.pin}\`.`,
		passed ? "- Every module read as its entry expects: the run passed." : "- The run failed:",
		...problems.map((p) => `  - ${line(p)}`),
		`- Modules: ${classes.map(count).join(", ")}.`,
		`- What it cannot show: ${cannotShow[input.run]}`,
		"",
		"## The provider as run: its differences from the pattern",
		"",
		...input.differences.map((d) => `- ${line(d)}`),
		"",
		"## How to read it",
		"",
		...notes.map((n) => `- ${n}`),
		"",
		"## Variants",
		"",
		...variants.map((v, i) => `- v${i + 1}: \`${v}\``),
		"",
		"## Modules",
		"",
		...table(
			[
				"Test",
				"Variant",
				"Result",
				"Class",
				"Observed",
				"Computed",
				"Unconfirmed (no entry names)",
				"Reviews",
			],
			modules.map((m) => [
				m.test,
				label(m.variant),
				m.result ?? "none",
				m.class,
				code(m.observed),
				code(m.computed),
				m.unconfirmed.join("; ") || "—",
				m.reviews.map((r) => `${r.src}: ${r.verdict}`).join("; ") || "—",
			]),
		),
		"",
		"## Refusals and conditions, block by block",
		"",
		...table(
			[
				"Test",
				"Variant",
				"Block",
				"Id",
				"Condition",
				"Refuser",
				"Place",
				"Status",
				"Words",
				"Reading",
			],
			modules.flatMap((m) => blockRows(m, label(m.variant))),
		),
		"",
		"## The ledger's rows the run names, and how",
		"",
		...table(
			["Key", "Named as", "Kind", "Standard", "Its text", "nextgen", "Why", "Decision"],
			[
				...input.ledger
					.filter((d) => named.has(d.key))
					.map((d) => [
						`\`${d.key}\``,
						howOf(d.key),
						d.kind,
						d.standard,
						d.text,
						d.behaviour,
						d.why,
						d.decision,
					]),
				...[...named.keys()]
					.filter((key) => !inLedger.has(key))
					.sort()
					.map((key) => [`\`${key}\``, howOf(key), "not in the ledger", "—", "—", "—", "—", "—"]),
			],
		),
		"",
		"## The harness's own tests, not the suite's evidence",
		"",
		"Each computed key's words in the word table, each with its case in `src/rp/test/words.process.test.ts`, which sends that cause alone from the harness's relying party to a scene, and the word it is answered in.",
		"",
		...table(["Computed key", "Case", "Its word"], backing),
	].join("\n")}\n`;
}
