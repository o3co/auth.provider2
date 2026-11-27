/**
 * The harness's Core's process: reads its spec from the file its argument names, starts
 * the Core, imports its seeds, and signals on its own descriptor (3), one JSON object a line: `ready` (the wire's port and
 * the key sets and the discovery document the operator publishes), each `mail` the Core sends, each `log` line, or `failed`.
 * Standard output is the modules' own (audit-stdout's records). SIGTERM, or its parent gone (standard
 * input ended), stops it.
 */
import { createWriteStream } from "node:fs";
import { readFile } from "node:fs/promises";
import type { Log } from "@mod/kernel";
import { startHere } from "./here.ts";
import { entry, type PatternSpec } from "./pattern.ts";

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
const { BootRefused } = await entry("@mod/kernel");

const writer =
	(level: string) =>
	(event: string, fields?: Record<string, unknown>): void => {
		say({ log: { level, event, fields: fields ?? {} } });
	};
const log: Log = {
	trace: writer("trace"),
	debug: writer("debug"),
	info: writer("info"),
	warn: writer("warn"),
	error: writer("error"),
	fatal: writer("fatal"),
};

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

try {
	const here = await startHere(spec, (mail) => say({ mail }), { log });
	app = here.app;
	say({
		ready: {
			port: here.port,
			jwks: { keys: here.jwks },
			coreKeys: { keys: [...here.ring, here.sealingKey] },
			metadata: here.metadata,
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
}
