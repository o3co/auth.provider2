import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * The provider's intended deviations from the standards and its strict choices (L1), as the ledger
 * `docs/compliance/deviations.json` holds them: what a conformance run's expected failures name by
 * key, and what the public compliance page is written from.
 */

/** A row: its key, its kind, the standard and its text, what nextgen does, why, and the decision. */
export interface Deviation {
	readonly key: string;
	/** `deviation`: the standard's normative text is not followed; `strict`: the standard allows it, and nextgen takes the strict side. */
	readonly kind: "deviation" | "strict";
	readonly standard: string;
	readonly text: string;
	readonly behaviour: string;
	readonly why: string;
	readonly decision: string;
}

const fields = ["key", "kind", "standard", "text", "behaviour", "why", "decision"] as const;
const kinds: readonly string[] = ["deviation", "strict"];
const keyForm = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;

/** The ledger's file and the page written from it, in the repository. */
const root = fileURLToPath(new URL("../../../../../", import.meta.url));
export const ledgerPath = `${root}docs/compliance/deviations.json`;
export const pagePath = `${root}docs/compliance/deviations.md`;

/** Why a ledger may not be taken: each problem named, none where it holds. */
export function ledgerProblems(value: unknown): string[] {
	if (!Array.isArray(value)) return ["the ledger is a list of rows"];
	const problems: string[] = [];
	const seen = new Set<string>();
	value.forEach((row, at) => {
		if (typeof row !== "object" || row === null || Array.isArray(row)) {
			problems.push(`row ${at + 1} is no object`);
			return;
		}
		const named = row as Record<string, unknown>;
		const extra = Object.keys(named).filter((k) => !(fields as readonly string[]).includes(k));
		if (extra.length > 0) problems.push(`row ${at + 1} has fields no row has: ${extra.join(", ")}`);
		for (const field of fields) {
			const v = named[field];
			if (typeof v !== "string" || v.trim() === "") problems.push(`row ${at + 1} has no ${field}`);
		}
		if (typeof named.key === "string") {
			if (!keyForm.test(named.key))
				problems.push(`row ${at + 1}'s key is not lowercase words joined by -`);
			if (seen.has(named.key)) problems.push(`the key ${named.key} is named twice`);
			seen.add(named.key);
		}
		if (typeof named.kind === "string" && !kinds.includes(named.kind))
			problems.push(`row ${at + 1}'s kind is neither deviation nor strict`);
	});
	return problems;
}

/** The ledger read, refused where any row may not be taken. */
export function ledgerOf(text: string): readonly Deviation[] {
	const value: unknown = JSON.parse(text);
	const problems = ledgerProblems(value);
	if (problems.length > 0) throw new Error(`the deviations ledger: ${problems.join("; ")}`);
	return value as Deviation[];
}

/** The ledger as the repository holds it. */
export const ledger = (): readonly Deviation[] => ledgerOf(readFileSync(ledgerPath, "utf8"));

/** A cell of the page's table: its text on one line, a `|` in it escaped. */
const cell = (text: string) => text.replace(/\r?\n/g, " ").replace(/\|/g, "\\|");

/** The public compliance page, written from the ledger: its rows in the ledger's order. */
export function pageOf(rows: readonly Deviation[]): string {
	const head = [
		"# Intended deviations and strict choices (L1)",
		"",
		"<!-- Written from deviations.json by `pnpm --filter @mod/interop-oidf run deviations`; edit the ledger, never this page. -->",
		"",
		"The provider runs the OpenID Foundation's conformance tests on its strongest configuration and publishes, for each test that fails, why it is deliberately strict, in terms of the threat model (L1). This is the list those explanations are written from. A conformance run's expected failures name a row by its key: a failure no expected entry explains fails the run, and so do an expected entry naming no row and an expected entry no test used. A row no run uses is kept: the list is of the provider's choices, not of one plan's.",
		"",
		"Gathering every other choice the design names is an L1 item for the gate. The rows below are the ones written so far.",
		"",
		"Two kinds of row:",
		"- **deviation**: the standard's normative text (MUST, MUST NOT) is not followed.",
		"- **strict**: the standard allows it, but nextgen takes the strict side, so a test expecting the permissive side fails.",
		"",
		"| Key | Kind | Standard | Its text | nextgen | Why | Decision |",
		"|---|---|---|---|---|---|---|",
	];
	const body = rows.map(
		(r) =>
			`| \`${r.key}\` | ${r.kind} | ${cell(r.standard)} | ${cell(r.text)} | ${cell(r.behaviour)} | ${cell(r.why)} | ${cell(r.decision)} |`,
	);
	return `${[...head, ...body].join("\n")}\n`;
}
