import { parseArgs } from "node:util";
import { generate } from "./generate.ts";
import { patterns } from "./patterns.ts";

/** Out and err, as the command writes them. */
export interface Io {
	readonly out: (text: string) => void;
	readonly err: (text: string) => void;
}

const usageText =
	"usage: create-app <target> --pattern <name> [--add <name>]... [--axis <owner>=<adapter>]...\n" +
	"       create-app --list   (each pattern, and what it is for)\n" +
	"       a name without a scope is @mod/'s: --add sign-up, --axis users=users-http\n";

/** A name without a scope is the workspace's own. */
const scopedName = (name: string) => (name.startsWith("@") ? name : `@mod/${name}`);

/** Runs the command: 0 once the app is written or `--help` or `--list` told, 64 for a usage error, 1 for an app it cannot make. */
export async function run(
	args: readonly string[],
	io: Io = { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) },
): Promise<number> {
	const usage = (why?: string) => {
		io.err(`${why ? `${why}\n` : ""}${usageText}`);
		return 64;
	};
	let parsed: ReturnType<
		typeof parseArgs<{ args: string[]; allowPositionals: true; options: typeof options }>
	>;
	const options = {
		help: { type: "boolean", short: "h" },
		list: { type: "boolean" },
		pattern: { type: "string" },
		add: { type: "string", multiple: true },
		axis: { type: "string", multiple: true },
	} as const;
	try {
		parsed = parseArgs({ args: [...args], allowPositionals: true, options });
	} catch (error) {
		return usage((error as Error).message);
	}
	const { values, positionals } = parsed;
	if (values.help) {
		io.out(usageText);
		return 0;
	}
	if (values.list) {
		if (positionals.length > 0 || values.pattern || values.add || values.axis) return usage();
		io.out(`${patterns.map((p) => `${p.name}: ${p.use}`).join("\n")}\n`);
		return 0;
	}
	const [target, ...more] = positionals;
	if (target === undefined || target.trim() === "" || more.length > 0) return usage();
	if (values.pattern === undefined) return usage("--pattern names the pattern");
	if (!patterns.some((p) => p.name === values.pattern)) {
		return usage(`${values.pattern}: not a pattern (${patterns.map((p) => p.name).join(", ")})`);
	}
	const pairs = (values.axis ?? []).map((pair) => pair.split("="));
	if (pairs.some((pair) => pair.length !== 2 || pair.includes(""))) return usage();
	try {
		const notices = await generate(target, {
			pattern: values.pattern,
			add: (values.add ?? []).map(scopedName),
			axes: Object.fromEntries(
				pairs.map(([owner, adapter]) => [scopedName(owner ?? ""), scopedName(adapter ?? "")]),
			),
		});
		for (const line of notices) io.err(`${line}\n`);
		io.out(`wrote ${values.pattern} to ${target}\n`);
		return 0;
	} catch (error) {
		io.err(`${(error as Error).message}\n`);
		return 1;
	}
}
