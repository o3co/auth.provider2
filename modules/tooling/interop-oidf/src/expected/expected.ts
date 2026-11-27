import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type Place, places, type Refuser, refusers } from "../words/words.ts";

/** A run's expected results, module by module, in the ledger's keys: `results` judges a run by them. */

/** What the suite reports of a module. */
export type SuiteResult = "PASSED" | "FAILED" | "WARNING" | "REVIEW" | "SKIPPED";

/**
 * How a module's result is read, the whole module's:
 * - `passed`: a module asking success, passed to its end;
 * - `own-condition`: a negative module passed (or a review approved), refused on the condition it tests;
 * - `before-wall`: a negative module passed, refused on another cause a ledger key names: no evidence;
 * - `explained`: failed, warned or a review failed, each condition by a ledger key;
 * - `unconfirmed`: what the words of a refusal cannot tell apart, known before the run; a review so read
 *   stays unapproved, and none fails a run;
 * - `skipped`: the suite skips it.
 */
export type Reading =
	| "passed"
	| "own-condition"
	| "before-wall"
	| "explained"
	| "unconfirmed"
	| "skipped";

/**
 * What one refusal shows: `observed`, a ledger row, its words that row's alone (its `keys` that one
 * row); `own`, the condition the module tests (no key); `unconfirmed`, words the table cannot tell
 * apart (its `keys`, where given, the rows they might be).
 */
export type RefusalReading = "observed" | "own" | "unconfirmed";

/** A refusal a module meets: in which block (by the suite's message for it), by whom, where, its status and words, and what it shows. */
export interface ExpectedRefusal {
	readonly block: string;
	readonly refuser: Refuser;
	readonly place: Place;
	readonly status: number;
	/** Its words; none where the answer has no body (a `404`). */
	readonly error?: string;
	readonly description?: string;
	readonly reading: RefusalReading;
	readonly keys?: readonly string[];
}

/** A FAILURE or WARNING the suite reports, by its condition (`src`), and the keys that explain it; none where unconfirmed. */
export interface ExpectedCondition {
	readonly src: string;
	readonly keys?: readonly string[];
}

/** One module's expected result. */
export interface Expected {
	/** The module, as the plan names it. */
	readonly test: string;
	/** The variant it runs under, as the plan gives it. */
	readonly variant: Readonly<Record<string, string>>;
	readonly result: SuiteResult;
	readonly reading: Reading;
	readonly refusals: readonly ExpectedRefusal[];
	readonly failures?: readonly ExpectedCondition[];
	readonly warnings?: readonly ExpectedCondition[];
}

/** The results each reading may have. */
const resultsOf: Readonly<Record<Reading, readonly SuiteResult[]>> = {
	passed: ["PASSED"],
	"own-condition": ["PASSED", "REVIEW"],
	"before-wall": ["PASSED"],
	explained: ["FAILED", "WARNING", "REVIEW"],
	unconfirmed: ["PASSED", "FAILED", "WARNING", "REVIEW"],
	skipped: ["SKIPPED"],
};
const suiteResults: readonly string[] = ["PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED"];
const refusalReadings: readonly string[] = ["observed", "own", "unconfirmed"];
const entryFields = ["test", "variant", "result", "reading", "refusals", "failures", "warnings"];
const refusalFields = [
	"block",
	"refuser",
	"place",
	"status",
	"error",
	"description",
	"reading",
	"keys",
];
/** A text that would match more than it names. */
const wildcard = /\*/;

const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/**
 * Why a file of expected results may not be taken, each problem named, none where it holds: plan §6's
 * (a key the ledger has not, a key twice, a field empty or of another type, a wildcard, an entry twice,
 * a variant that is no object of texts), a field none has, and a reading without the parts that say it
 * or with a result it may not have.
 */
export function expectedProblems(value: unknown, ledgerKeys: readonly string[]): string[] {
	if (!Array.isArray(value)) return ["the expected results are a list of entries"];
	const problems: string[] = [];
	const seen = new Set<string>();
	const extraIn = (o: Record<string, unknown>, known: readonly string[], of: string) => {
		const extra = Object.keys(o).filter((k) => !known.includes(k));
		if (extra.length > 0) problems.push(`${of} has fields none has: ${extra.join(", ")}`);
	};
	const keysOf = (keys: unknown, of: string) => {
		if (!Array.isArray(keys) || keys.length === 0) {
			problems.push(`${of} names no key`);
			return;
		}
		const named = new Set<unknown>();
		for (const key of keys) {
			if (!text(key)) problems.push(`${of} has a key that is no text`);
			else if (!ledgerKeys.includes(key))
				problems.push(`${of} names ${key}, which the ledger has not`);
			if (named.has(key)) problems.push(`${of} names ${key} twice`);
			named.add(key);
		}
	};
	const conditionsOf = (list: unknown, of: string) => {
		if (list === undefined) return [];
		if (!Array.isArray(list)) {
			problems.push(`${of} are no list`);
			return [];
		}
		list.forEach((c, i) => {
			const one = `${of.replace(/s$/, "")} ${i + 1}`;
			if (!isObject(c) || !text(c.src)) {
				problems.push(`${one} names no condition`);
				return;
			}
			extraIn(c, ["src", "keys"], one);
			if (wildcard.test(c.src)) problems.push(`${one}'s condition is a wildcard`);
			if (c.keys !== undefined) keysOf(c.keys, one);
		});
		return list.filter(isObject);
	};
	value.forEach((entry, at) => {
		const where = `entry ${at + 1}`;
		if (!isObject(entry)) {
			problems.push(`${where} is no object`);
			return;
		}
		extraIn(entry, entryFields, where);
		if (!text(entry.test)) problems.push(`${where} names no test`);
		else if (wildcard.test(entry.test)) problems.push(`${where}'s test is a wildcard`);
		const variant = entry.variant;
		if (
			!isObject(variant) ||
			Object.keys(variant).length === 0 ||
			!Object.entries(variant).every(([k, v]) => text(k) && text(v) && !wildcard.test(k + v))
		)
			problems.push(`${where}'s variant is no object of texts`);
		if (!suiteResults.includes(entry.result as string))
			problems.push(`${where}'s result is none the suite reports`);
		const reading = entry.reading as Reading;
		if (!Object.hasOwn(resultsOf, reading)) problems.push(`${where}'s reading is none known`);
		else if (!resultsOf[reading].includes(entry.result as SuiteResult))
			problems.push(`${where} is ${reading}, which a ${String(entry.result)} is not`);
		const refusals = Array.isArray(entry.refusals) ? entry.refusals : [];
		if (!Array.isArray(entry.refusals)) problems.push(`${where} has no list of refusals`);
		refusals.forEach((r, i) => {
			const of = `${where}'s refusal ${i + 1}`;
			if (!isObject(r)) {
				problems.push(`${of} is no object`);
				return;
			}
			extraIn(r, refusalFields, of);
			if (!text(r.block)) problems.push(`${of} has no block`);
			else if (wildcard.test(r.block)) problems.push(`${of}'s block is a wildcard`);
			if (!(refusers as readonly unknown[]).includes(r.refuser))
				problems.push(`${of}'s refuser is none known`);
			if (!(places as readonly unknown[]).includes(r.place))
				problems.push(`${of}'s place is none known`);
			if (!Number.isInteger(r.status) || (r.status as number) < 400 || (r.status as number) > 599)
				problems.push(`${of}'s status is no refusal's`);
			// Words both or neither: none only where the answer has no body.
			if ((r.error === undefined) !== (r.description === undefined))
				problems.push(`${of} has an error or a description, not both`);
			for (const field of ["error", "description"] as const)
				if (r[field] !== undefined && !text(r[field])) problems.push(`${of} has an empty ${field}`);
				else if (text(r[field]) && wildcard.test(r[field]))
					problems.push(`${of}'s ${field} is a wildcard`);
			if (!refusalReadings.includes(r.reading as string))
				problems.push(`${of}'s reading is none known`);
			if (r.reading === "observed") {
				keysOf(r.keys, of);
				if (Array.isArray(r.keys) && r.keys.length !== 1)
					problems.push(`${of} is observed, of one row`);
				if (r.error === undefined) problems.push(`${of} is observed, by no words`);
			}
			if (r.reading === "own" && r.keys !== undefined)
				problems.push(`${of} is the test's own, yet names a key`);
			if (r.reading === "unconfirmed" && r.keys !== undefined) keysOf(r.keys, of);
		});
		const failures = conditionsOf(entry.failures, `${where}'s failures`);
		const warnings = conditionsOf(entry.warnings, `${where}'s warnings`);
		const conditions = [...failures, ...warnings];
		const readingsOfRefusals = refusals.filter(isObject).map((r) => r.reading);
		if (entry.result === "FAILED" && failures.length === 0)
			problems.push(`${where} failed by no condition`);
		if (entry.result !== "FAILED" && failures.length > 0)
			problems.push(`${where} names failures, yet does not fail`);
		if (entry.result === "WARNING" && warnings.length === 0)
			problems.push(`${where} warned by no condition`);
		// Each reading holds the parts that say it.
		if (reading === "own-condition" && !readingsOfRefusals.includes("own"))
			problems.push(`${where} passed on its own condition by no refusal of it`);
		if (reading === "before-wall" && !readingsOfRefusals.includes("observed"))
			problems.push(`${where} passed before the wall by no cause observed`);
		if (reading === "explained" && conditions.some((c) => c.keys === undefined))
			problems.push(`${where} is explained, yet a condition names no key`);
		if (reading === "explained" && !readingsOfRefusals.includes("observed"))
			problems.push(`${where} is explained by no cause observed`);
		// A condition is explained by a key observed, never by one no refusal shows (decision 12).
		const observedKeys = new Set(
			refusals
				.filter((r) => isObject(r) && r.reading === "observed" && Array.isArray(r.keys))
				.flatMap((r) => r.keys as unknown[]),
		);
		for (const c of conditions)
			for (const key of Array.isArray(c.keys) ? c.keys : [])
				if (!observedKeys.has(key))
					problems.push(`${where} explains ${c.src} by ${key}, which no refusal shows`);
		if (
			(reading === "passed" || reading === "own-condition") &&
			readingsOfRefusals.includes("observed")
		)
			problems.push(`${where} is ${reading}, yet a refusal shows a ledger row`);
		if (entry.result === "PASSED" && warnings.length > 0)
			problems.push(`${where} passed, yet names warnings`);
		if (
			reading === "unconfirmed" &&
			!readingsOfRefusals.includes("unconfirmed") &&
			!conditions.some((c) => c.keys === undefined)
		)
			problems.push(`${where} is unconfirmed by nothing the words leave apart`);
		if ((reading === "passed" || reading === "skipped") && conditions.length > 0)
			problems.push(`${where} is ${reading}, yet names a condition`);
		if (reading === "skipped" && refusals.length > 0)
			problems.push(`${where} is skipped, yet meets a refusal`);
		if (text(entry.test) && isObject(variant)) {
			const sorted = Object.entries(variant).sort(([a], [b]) => a.localeCompare(b));
			const name = `${entry.test} ${JSON.stringify(sorted)}`;
			if (seen.has(name)) problems.push(`${where} names ${entry.test} under its variant again`);
			seen.add(name);
		}
	});
	return problems;
}

/** Expected results read from a text, refused where any entry may not be taken. */
export function expectedOf(text: string, ledgerKeys: readonly string[]): readonly Expected[] {
	const value: unknown = JSON.parse(text);
	const problems = expectedProblems(value, ledgerKeys);
	if (problems.length > 0)
		throw new Error(`the expected results may not be taken:\n${problems.join("\n")}`);
	return value as readonly Expected[];
}

/** The package's file of a run's expected results (`expected/<run>.json`). */
export const expectedPath = (run: string) =>
	fileURLToPath(new URL(`../../expected/${run}.json`, import.meta.url));

/** A run's expected results, the package's file, held to the ledger's keys. */
export const expectedFor = (run: string, ledgerKeys: readonly string[]) =>
	expectedOf(readFileSync(expectedPath(run), "utf8"), ledgerKeys);
