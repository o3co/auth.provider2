/**
 * The default pattern's process (M4's seed): reads its spec from the file its argument names, starts
 * the Core, and signals on its own descriptor (3), one JSON object a line: `ready` (the wire's port and
 * the key sets the operator publishes), each `mail` the Core sends, each `log` line, or `failed`.
 * Standard output is the modules' own (audit-stdout's records). SIGTERM, or its parent gone (standard
 * input ended), stops it.
 */
import { createWriteStream } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { entry, type PatternSpec, pattern } from "./pattern.ts";

const signals = createWriteStream("", { fd: 3 });
const say = (line: Record<string, unknown>) =>
	signals.write(
		`${JSON.stringify(line, (_key, value) =>
			value instanceof Error
				? { error: value.name }
				: typeof value === "bigint"
					? `${value}`
					: value,
		)}\n`,
	);

const spec: PatternSpec = JSON.parse(await readFile(process.argv[2] ?? "", "utf8"));
const { assemble, BootRefused } = await entry("@mod/kernel");
const { quietRuntime } = await entry("@mod/kernel", "./testing");
const { listening } = await entry("@mod/http");
const { keys } = await entry("@mod/keys");

const writer = (level: string) => (event: string, fields?: Record<string, unknown>) =>
	say({ log: { level, event, fields: fields ?? {} } });
const log = Object.fromEntries(
	["trace", "debug", "info", "warn", "error"].map((level) => [level, writer(level)]),
);

let stopping: Promise<void> | undefined;
let app: { stop(ms: number): Promise<void> } | undefined;
const stop = () => {
	if (stopping !== undefined) return;
	stopping = (async () => {
		await app?.stop(2000);
		signals.end(() => process.exit(0));
	})();
};
process.once("SIGTERM", stop);
process.stdin.on("end", stop).resume();

const dir = await mkdtemp(join(tmpdir(), "pattern-keys-"));
try {
	const { modules, config } = await pattern(spec, (mail) => say({ mail }));
	const started = await assemble({ modules, config, runtime: quietRuntime({ log }) });
	app = started;
	await started.start();
	// The key sets as the operator publishes them: the JWKS, and the Core's ring with its sealing key.
	const published = await started.get(keys).publish([dir]);
	if (published.code !== 0) throw new Error(`keys-publish: ${published.lines.join(" ")}`);
	const read = async (name: string) => JSON.parse(await readFile(join(dir, name), "utf8"));
	say({
		ready: {
			port: started.get(listening).port(),
			jwks: await read("jwks.json"),
			coreKeys: await read("core-keys.json"),
		},
	});
} catch (error) {
	say({
		failed: BootRefused.is(error)
			? { refusals: (error as { refusals: unknown }).refusals }
			: { error: String((error as Error)?.stack ?? error) },
	});
	process.exitCode = 1;
	signals.end();
} finally {
	await rm(dir, { recursive: true, force: true });
}
