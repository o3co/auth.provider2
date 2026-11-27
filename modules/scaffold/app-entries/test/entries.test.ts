import { expect, it } from "vitest";
import { type Declaring, entriesOf } from "../src/contract.ts";
import type { Shape } from "../src/entries/declared.ts";
import { mainSource } from "../src/start.ts";
import { declaring } from "./fixtures/declaring.ts";

// The tests of how entries are written and declared, none running one: those that run the
// written entries as child processes are in `entries.process.test.ts`.
const ignored = (path: string) => `node ${path}`;
const refusal = (entries: readonly Declaring[], modules = ["@mod/tool", "@mod/other"]) =>
	entriesOf(modules, (name) => name, ignored, undefined, entries);

it.each([
	["a list", [{ name: "@mod/tool", appEntries: { script: "tool" } }], "appEntries is not a list"],
	["an object", [{ name: "@mod/tool", appEntries: ["tool"] }], "an entry is not an object"],
	[
		"a script's name",
		declaring({ script: "Tool" }),
		"a script is not a lowercase name other than start",
	],
	["start", declaring({ script: "start" }), "a script is not a lowercase name other than start"],
	[
		"a shape",
		declaring({ shape: "stream" }),
		"tool's shape is not one of call, settle-subjects, settle-records, name-subjects",
	],
	["a key", declaring({ fill: {} }), "tool has keys its shape does not take: fill"],
	[
		"answers on a call",
		declaring({ answers: ["done"] }),
		"tool has keys its shape does not take: answers",
	],
	[
		"answers on naming",
		declaring({ shape: "name-subjects", answers: ["done"] }),
		"keys its shape does not take: answers",
	],
	["a contract", declaring({ contract: "tool-run" }), "tool's contract is not a name"],
	["a member", declaring({ member: "run()" }), "tool's member is not a name"],
	[
		"no answers",
		declaring({ shape: "settle-subjects" }),
		"tool's answers are not a list of at least one",
	],
	[
		"empty answers",
		declaring({ shape: "settle-subjects", answers: [] }),
		"tool's answers are not a list of at least one",
	],
	[
		"a word",
		declaring({ shape: "settle-subjects", answers: ['marked"]'] }),
		"tool's answers are not each a lowercase word",
	],
	[
		"an answer twice",
		declaring({ shape: "settle-subjects", answers: ["marked", "marked"] }),
		"tool names an answer twice",
	],
	[
		"the script's own count",
		declaring({ shape: "settle-subjects", answers: ["marked", "failed"] }),
		"names an answer the script counts itself",
	],
	[
		"no answers to records",
		declaring({ shape: "settle-records" }),
		"tool's answers are not a list of at least one",
	],
	[
		"a limit of none",
		declaring({ shape: "answer-lines" }),
		"tool's longest is not a whole number of bytes from 1 to 65536",
	],
	[
		"a limit of 0",
		declaring({ shape: "answer-lines", longest: 0 }),
		"tool's longest is not a whole number of bytes from 1 to 65536",
	],
	[
		"a limit of 65537",
		declaring({ shape: "answer-lines", longest: 65537 }),
		"tool's longest is not a whole number of bytes from 1 to 65536",
	],
	[
		"a limit of 1.5",
		declaring({ shape: "answer-lines", longest: 1.5 }),
		"tool's longest is not a whole number of bytes from 1 to 65536",
	],
	[
		"a limit of text",
		declaring({ shape: "answer-lines", longest: "64" }),
		"tool's longest is not a whole number of bytes from 1 to 65536",
	],
	[
		"answers on answer lines",
		declaring({ shape: "answer-lines", longest: 64, answers: ["done"] }),
		"keys its shape does not take: answers",
	],
	[
		"a script declared twice",
		[...declaring({}), ...declaring({}, "@mod/other")],
		"@mod/other declares appEntries that cannot be read: tool is declared by @mod/tool too",
	],
])("refuses a declaration that is not %s, naming its package", async (_, entries, why) => {
	const refused = await refusal(entries).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(TypeError);
	expect((refused as Error).message).toContain("declares appEntries that cannot be read");
	expect((refused as Error).message).toContain(why);
});

it("reads only what the composed packages declare, and writes each declared script from its declaration", async () => {
	const ignoredElsewhere = await refusal([{ name: "@mod/elsewhere", appEntries: "not read" }]);
	expect(ignoredElsewhere.scripts).toEqual({});
	const declared = declaring(
		{
			script: "settled",
			shape: "settle-subjects",
			member: "settle",
			answers: ["marked", "held"],
		},
		"@mod/settler",
	);
	const { scripts, files } = await entriesOf(
		["@mod/settler"],
		(name) => name,
		ignored,
		undefined,
		declared,
	);
	expect(scripts).toEqual({ settled: "node src/settled.ts" });
	expect(files["src/settled.ts"]).toContain(
		'const answers: readonly string[] = ["marked", "held"];',
	);
	expect(files["src/settled.ts"]).toContain("{ toolRun: declaredContract }");
});

it("assembles every tool shape never to start, and the app's entry to start", async () => {
	// Each shape, so a shape added later fails to compile here until it is pinned too.
	const fields = {
		call: {},
		"settle-subjects": { answers: ["marked"] },
		"settle-records": { answers: ["kept"] },
		"name-subjects": {},
		"answer-lines": { longest: 64 },
	} satisfies Record<Shape, Record<string, unknown>>;
	for (const [shape, extra] of Object.entries(fields)) {
		const { files } = await entriesOf(
			["@mod/tool"],
			(name) => name,
			ignored,
			undefined,
			declaring({ shape, ...extra }),
		);
		expect(files["src/tool.ts"], shape).toMatch(/assemble\(\{[^}]*neverStarted: true[^}]*\}\)/);
	}
	expect(await mainSource(["@mod/tool"])).not.toContain("neverStarted");
});
