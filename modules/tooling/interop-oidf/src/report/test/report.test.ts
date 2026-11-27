import { describe, expect, it } from "vitest";
import type { Deviation } from "../../deviations/deviations.ts";
import { ledger } from "../../deviations/deviations.ts";
import type { Judged, MetCondition, RunRefusal } from "../../results/test/results.ts";
import { words } from "../../words/words.ts";
import { type ReportInput, reportOf } from "./report.ts";

const variant = { openid: "openid_connect", client_auth_type: "private_key_jwt" };
const test = "fapi2-message-signing-final-happy-flow";
const par = "Make request to PAR endpoint";
const typ: RunRefusal = {
	block: par,
	blockId: "b1",
	place: "par",
	status: 400,
	error: "invalid_request_object",
	description: "not of the typ asked",
	refuser: "core",
	reading: { kind: "observed", key: "jar-typ-required" },
};
const condition = (over: Partial<MetCondition> = {}): MetCondition => ({
	kind: "FAILURE",
	src: "CheckPAREndpointResponse201WithNoError",
	block: par,
	blockId: "b1",
	named: true,
	keys: ["jar-typ-required"],
	unshown: [],
	...over,
});
const module = (over: Partial<Judged> = {}): Judged => ({
	test,
	variant,
	result: "FAILED",
	class: "explained",
	blocks: [{ id: "b1", message: par }],
	refusals: [typ],
	conditions: [condition()],
	observed: ["jar-typ-required"],
	computed: ["jar-typ-required"],
	problems: [],
	unconfirmed: [],
	reviews: [],
	...over,
});
const row = (key: string, over: Partial<Deviation> = {}): Deviation => ({
	key,
	kind: "strict",
	standard: "RFC 9101",
	text: "its text",
	behaviour: "what it does",
	why: "why",
	decision: "F4",
	...over,
});
const judgedOf = (...modules: Judged[]) => ({ modules, problems: [], passed: true });
const input = (over: Partial<ReportInput> = {}): ReportInput => ({
	run: "A",
	plan: "fapi2-message-signing-final-test-plan",
	pin: "release-v5.3.5 246b2c14",
	differences: ["`sign-up` added", "one\nsender"],
	judged: judgedOf(module()),
	ledger: [row("jar-typ-required"), row("unused-row")],
	...over,
});
/** A section's lines, from its heading to the next. */
const section = (text: string, heading: string) => {
	const all = text.split("\n");
	const from = all.indexOf(heading);
	expect(from, heading).toBeGreaterThan(-1);
	const to = all.findIndex((l, i) => i > from && l.startsWith("## "));
	return all.slice(from, to < 0 ? undefined : to);
};
const tableRows = (lines: readonly string[]) => lines.filter((l) => l.startsWith("| ")).slice(1);

describe("a run's report", () => {
	it("heads with the plan, the pin, what passing means or why it failed, the classes, and what run A cannot show", () => {
		const passed = reportOf(input());
		expect(passed).toContain(
			"- Plan: `fapi2-message-signing-final-test-plan`, the suite at `release-v5.3.5 246b2c14`.",
		);
		expect(passed).toContain("- Every module read as its entry expects: the run passed.");
		expect(passed).toContain(
			"- Modules: crossed 0, before-wall 0, explained 1, unconfirmed 0, skipped 0, failed 0.",
		);
		expect(passed).toContain(
			"- What it cannot show: Run A gives no evidence of the token endpoint, the resource, DPoP past PAR, or refresh",
		);
		expect(passed).toContain("That is run B's");
		const judged = {
			modules: [module({ class: "failed" })],
			problems: ["x failed:\na"],
			passed: false,
		};
		const failed = reportOf(input({ judged })).split("\n");
		expect(failed).toEqual(expect.arrayContaining(["- The run failed:", "  - x failed: a"]));
		expect(failed).not.toContain("- Every module read as its entry expects: the run passed.");
	});

	it("names the scene's differences, each on one line, and says how to read each class and key", () => {
		const text = reportOf(input());
		expect(section(text, "## The provider as run: its differences from the pattern")).toEqual(
			expect.arrayContaining(["- `sign-up` added", "- one sender"]),
		);
		const how = section(text, "## How to read it").join("\n");
		for (const said of [
			"`before-wall`, passed but refused on another cause a ledger row names, no evidence",
			"only an observed key explains (decision 12)",
			"shown beside and never compared",
			"An empty text in a JAR is a value, judged by its item's rule",
			"but `request`'s and `request_uri`'s",
			"A review's verdict is the harness's own record",
		])
			expect(how).toContain(said);
	});

	it("gives a module its variant's label, its keys, the unconfirmed no entry names, and its reviews' verdicts", () => {
		const other = module({
			variant: { client_auth_type: "private_key_jwt", openid: "plain_oauth" },
			result: "REVIEW",
			unconfirmed: ["Client assertion without sub: the client is not authenticated"],
			reviews: [
				{ test, src: "VerifyErrorPage", verdict: "explained", why: "explained: explained" },
			],
		});
		const text = reportOf(input({ judged: judgedOf(module(), other) }));
		expect(section(text, "## Variants")).toEqual(
			expect.arrayContaining([
				'- v1: `{"client_auth_type":"private_key_jwt","openid":"openid_connect"}`',
				'- v2: `{"client_auth_type":"private_key_jwt","openid":"plain_oauth"}`',
			]),
		);
		const modules = section(text, "## Modules");
		expect(modules[2]).toContain("| Unconfirmed (no entry names) |");
		expect(tableRows(modules)).toEqual([
			`| ${test} | v1 | FAILED | explained | \`jar-typ-required\` | \`jar-typ-required\` | — | — |`,
			`| ${test} | v2 | REVIEW | explained | \`jar-typ-required\` | \`jar-typ-required\` | Client assertion without sub: the client is not authenticated | VerifyErrorPage: explained |`,
		]);
	});

	it("lists refusals and conditions block by block in the log's order, by each block's id, outside every block last", () => {
		const client: RunRefusal = {
			...typ,
			block: "Client assertion without sub",
			blockId: "b2",
			status: 401,
			error: "invalid_client",
			description: "the client is not authenticated",
			reading: { kind: "unconfirmed", keys: [] },
		};
		const { error: _e, description: _d, ...bare } = typ;
		const loose: RunRefusal = {
			...bare,
			block: "no block",
			blockId: "undefined",
			refuser: "front",
			status: 404,
			reading: { kind: "none" },
		};
		const shared: RunRefusal = {
			...typ,
			blockId: "b3",
			reading: { kind: "unconfirmed", keys: ["a-row", "b-row"] },
		};
		const m = module({
			// b0 comes first in the log though only a condition was logged there; b3 shares b1's message.
			blocks: [
				{ id: "b0", message: "Early block" },
				{ id: "b1", message: par },
				{ id: "b2", message: "Client assertion without sub" },
				{ id: "b3", message: par },
			],
			refusals: [loose, typ, client, shared],
			conditions: [
				condition({ kind: "WARNING", src: "Early", block: "Early block", blockId: "b0", keys: [] }),
				condition(),
				condition({ src: "Unnamed", blockId: "b2", block: client.block, named: false, keys: [] }),
				condition({ src: "Unshown", blockId: "b3", unshown: ["jar-typ-required"] }),
			],
		});
		const rows = tableRows(
			section(
				reportOf(input({ judged: judgedOf(m) })),
				"## Refusals and conditions, block by block",
			),
		);
		const f = `| ${test} | v1 |`;
		expect(rows).toEqual([
			`${f} Early block | b0 | WARNING Early | — | — | — | — | named, by no key |`,
			`${f} ${par} | b1 | — | core | par | 400 | invalid_request_object: not of the typ asked | observed \`jar-typ-required\` |`,
			`${f} ${par} | b1 | FAILURE CheckPAREndpointResponse201WithNoError | — | — | — | — | by \`jar-typ-required\` |`,
			`${f} Client assertion without sub | b2 | — | core | par | 401 | invalid_client: the client is not authenticated | unconfirmed (many causes) |`,
			`${f} Client assertion without sub | b2 | FAILURE Unnamed | — | — | — | — | no entry names it |`,
			`${f} ${par} | b3 | — | core | par | 400 | invalid_request_object: not of the typ asked | unconfirmed (\`a-row\`, \`b-row\`) |`,
			`${f} ${par} | b3 | FAILURE Unshown | — | — | — | — | by \`jar-typ-required\`; its block shows not \`jar-typ-required\` |`,
			`${f} no block | — | — | front | par | 404 | no words | no row |`,
		]);
	});

	it("shows each ledger row the run names in the ledger's order, how each is named, a key of no row, each cell on one line", () => {
		const m = module({
			observed: ["jar-typ-required"],
			computed: ["jar-jti-required"],
			refusals: [{ ...typ, reading: { kind: "unconfirmed", keys: ["jar-required"] } }],
			conditions: [condition({ keys: ["par-jar-lifetime", "jar-typ-required"] })],
		});
		const extra = module({ observed: [], computed: ["no-such-row"], refusals: [], conditions: [] });
		const rows = [
			row("par-jar-lifetime"),
			row("unused-row"),
			row("jar-required", { behaviour: "a | b\r\nc\rd <b>e</b>" }),
			row("jar-typ-required"),
			row("jar-jti-required"),
		];
		const text = section(
			reportOf(input({ judged: judgedOf(m, extra), ledger: rows })),
			"## The ledger's rows the run names, and how",
		);
		expect(tableRows(text)).toEqual([
			"| `par-jar-lifetime` | a condition's | strict | RFC 9101 | its text | what it does | why | F4 |",
			"| `jar-required` | unconfirmed | strict | RFC 9101 | its text | a \\| b c d &lt;b>e&lt;/b> | why | F4 |",
			"| `jar-typ-required` | observed, a condition's | strict | RFC 9101 | its text | what it does | why | F4 |",
			"| `jar-jti-required` | computed | strict | RFC 9101 | its text | what it does | why | F4 |",
			"| `no-such-row` | computed | not in the ledger | — | — | — | — | — |",
		]);
	});

	it("backs each computed key, once and in order, by the harness's case for each of its words and what tells them apart", () => {
		const wordless = ledger().find((d) => !words.some((w) => w.key === d.key))?.key ?? "";
		expect(wordless).not.toBe("");
		const a = module({ computed: ["par-dpop-header-only", "jar-typ-required"] });
		const b = module({ computed: [wordless, "jar-typ-required", "jar-dpop-jkt-required"] });
		const rows = tableRows(
			section(
				reportOf(input({ judged: judgedOf(a, b), ledger: ledger() })),
				"## The harness's own tests, not the suite's evidence",
			),
		);
		const sayOf = (key: string, place: string) => {
			const w = words.find((x) => x.key === key && x.place === place);
			return `${w?.refuser} at ${place}: ${w?.error}: ${w?.description}`;
		};
		const keys = rows.map((r) => r.split(" | ")[0]?.slice(2));
		expect(keys).toEqual([...keys].sort());
		expect(rows).toContain(
			`| \`jar-typ-required\` | jar-typ-required/par | ${sayOf("jar-typ-required", "par")} |`,
		);
		expect(rows.filter((r) => r.startsWith("| `jar-typ-required`"))).toHaveLength(
			words.filter((w) => w.key === "jar-typ-required").length,
		);
		expect(rows).toContain(
			`| \`jar-dpop-jkt-required\` | jar-dpop-jkt-required/par | ${sayOf("jar-dpop-jkt-required", "par")} (with no DPoP header) |`,
		);
		expect(rows).toContain(
			`| \`par-dpop-header-only\` | par-dpop-header-only/par | ${sayOf("par-dpop-header-only", "par")} (with a DPoP header) |`,
		);
		expect(rows).toContain(`| \`${wordless}\` | none: no refusal shows it | — |`);
	});
});
