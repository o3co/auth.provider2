import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Readable } from "node:stream";
import type { PatternSpec, SentMail } from "./pattern.ts";

/** A JWK as a key set publishes it. */
export type PublishedKey = Record<string, string> & { readonly kid: string };

/** A line of the Core's log, as its process wrote it. */
export interface CoreLine {
	readonly level: string;
	readonly event: string;
	readonly fields: Record<string, unknown>;
}

/** What a test waits for in what the Core wrote: the first item `matches` takes, within `withinMs`. */
export type Waiting<T> = (matches: (item: T) => boolean, withinMs?: number) => Promise<T>;

/** A Core the default pattern started in a process of its own: what a test may know of it. */
export interface StartedCore {
	/** The wire's port on localhost, for a Front's `wireClient`. */
	readonly port: number;
	/** The authority's JWKS (ID tokens, access tokens), as published. */
	readonly jwks: readonly PublishedKey[];
	/** The Core's ring, the statements' keys, as the screen pins them. */
	readonly ring: readonly PublishedKey[];
	/** The Core's sealing key (HPKE, P-256), as the screen pins it. */
	readonly sealingKey: PublishedKey;
	/** The mails the Core sent so far, and a wait for one: a mail goes apart from the wire's answer. */
	readonly mail: () => readonly SentMail[];
	readonly mailWhere: Waiting<SentMail>;
	/** The Core's log so far, and a wait for a line. */
	readonly lines: () => readonly CoreLine[];
	readonly lineWhere: Waiting<CoreLine>;
	/** The audit records the Core wrote (audit-stdout), and any other line of its output, as written. */
	readonly audit: () => readonly Record<string, unknown>[];
	readonly output: () => readonly string[];
	/** Throws where the Core's process ended before it was told to stop, with what it wrote on stderr. */
	readonly alive: () => void;
	readonly stop: () => Promise<void>;
}

const child = join(import.meta.dirname, "child.ts");

/** How long a Core may take to start, and to stop once told, before it is killed. */
export const readyWithinMs = 20_000;
const stopWithinMs = 5_000;

/** Each JSON line a stream carries, and each other line apart. */
function linesOf(
	stream: Readable,
	json: (value: Record<string, unknown>) => void,
	other: (line: string) => void,
) {
	createInterface({ input: stream }).on("line", (text) => {
		try {
			const value = JSON.parse(text);
			if (value !== null && typeof value === "object") json(value);
			else other(text);
		} catch {
			other(text);
		}
	});
}

/** A wait over a growing list, polled at the event loop's pace, refused past `withinMs`. */
function waitingOver<T>(items: readonly T[], what: string): Waiting<T> {
	return (matches, withinMs = 5_000) =>
		new Promise((resolve, reject) => {
			const until = Date.now() + withinMs;
			const look = () => {
				const found = items.find(matches);
				if (found !== undefined) return resolve(found);
				if (Date.now() > until) return reject(new Error(`no ${what} within ${withinMs} ms`));
				setTimeout(look, 10);
			};
			look();
		});
}

/** Starts the default pattern in a child process, ready once it has published its keys. */
export async function startCore(spec: PatternSpec): Promise<StartedCore> {
	const dir = await mkdtemp(join(tmpdir(), "pattern-spec-"));
	const specFile = join(dir, "spec.json");
	await writeFile(specFile, JSON.stringify(spec));
	// Standard input stays open: the child stops when it ends, so a test process that dies takes it along.
	const process_ = spawn(process.execPath, [child, specFile], {
		stdio: ["pipe", "pipe", "pipe", "pipe"],
	});
	const mail: SentMail[] = [];
	const lines: CoreLine[] = [];
	const audit: Record<string, unknown>[] = [];
	const output: string[] = [];
	const errors: string[] = [];
	process_.stderr.on("data", (chunk) => errors.push(String(chunk)));
	linesOf(
		process_.stdout,
		(record) => audit.push(record),
		(line) => output.push(line),
	);
	const closed = new Promise<number | null>((resolve) => process_.once("close", resolve));
	let told = false;
	const ready = new Promise<Record<string, unknown>>((resolve, reject) => {
		const timer = setTimeout(
			() => reject(new Error("the Core was not ready in time")),
			readyWithinMs,
		);
		linesOf(
			process_.stdio[3] as Readable,
			(said) => {
				if (said.mail) mail.push(said.mail as SentMail);
				else if (said.log) lines.push(said.log as CoreLine);
				else if (said.ready) {
					clearTimeout(timer);
					resolve(said.ready as Record<string, unknown>);
				} else if (said.failed) {
					clearTimeout(timer);
					reject(new Error(`the Core did not start: ${JSON.stringify(said.failed)}`));
				}
			},
			(line) => output.push(line),
		);
		closed.then((code) => {
			clearTimeout(timer);
			reject(new Error(`the Core's process ended (${code}): ${errors.join("")}`));
		});
	});
	const orphaned = () => process_.kill("SIGKILL");
	process.once("exit", orphaned);
	const ended = () => process_.exitCode !== null || process_.signalCode !== null;
	/** SIGTERM, the Core's own drain; SIGKILL past `stopWithinMs`; then its spec removed. */
	const stop = async () => {
		const early = ended() && !told;
		told = true;
		if (!ended()) {
			process_.kill("SIGTERM");
			const late = setTimeout(() => process_.kill("SIGKILL"), stopWithinMs);
			await closed;
			clearTimeout(late);
		}
		process.removeListener("exit", orphaned);
		await rm(dir, { recursive: true, force: true });
		if (early) throw new Error(`the Core's process had ended before its stop: ${errors.join("")}`);
	};
	try {
		const said = await ready;
		const core = (said.coreKeys as { keys: PublishedKey[] }).keys;
		const sealing = core.filter((key) => key.use === "enc");
		const [sealingKey] = sealing;
		if (sealingKey === undefined || sealing.length !== 1)
			throw new Error("not one sealing key published");
		return {
			port: said.port as number,
			jwks: (said.jwks as { keys: PublishedKey[] }).keys,
			ring: core.filter((key) => key.use !== "enc"),
			sealingKey,
			mail: () => mail,
			mailWhere: waitingOver(mail, "mail"),
			lines: () => lines,
			lineWhere: waitingOver(lines, "log line"),
			audit: () => audit,
			output: () => output,
			alive: () => {
				if (ended() && !told) throw new Error(`the Core's process ended: ${errors.join("")}`);
			},
			stop,
		};
	} catch (error) {
		await stop().catch(() => {});
		throw error;
	}
}
