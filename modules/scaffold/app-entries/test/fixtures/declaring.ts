import type { Declaring } from "../../src/contract.ts";

/** What a package of the fakes declares: one entry, of the tool's contract unless said. */
export const declaring = (entry: Record<string, unknown>, name = "@mod/tool"): Declaring[] => [
	{
		name,
		appEntries: [{ script: "tool", shape: "call", contract: "toolRun", member: "run", ...entry }],
	},
];
