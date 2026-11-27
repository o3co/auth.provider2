import { execFile } from "node:child_process";
import { promisify } from "node:util";

/**
 * A program other than docker run for a plan (docker's is `docker-client`'s): held to its own time, and to the plan's deadline where it is given one.
 * Answers what it wrote to each stream apart: `stdout` alone is what a caller parses, `stderr` its
 * diagnostics (left out by a command that has none to tell).
 */
export type Command = (
	cmd: string,
	args: readonly string[],
	options: {
		readonly timeoutMs: number;
		readonly signal?: AbortSignal;
	},
) => Promise<{ readonly stdout: string; readonly stderr?: string }>;

/** The most a command may write to either stream before it is stopped. */
const largestCommandOutputBytes = 64 * 1024 * 1024;

/** The system's commands, killed past their time or at the deadline. */
export const systemCommand: Command = async (cmd, args, options) => {
	const { stdout, stderr } = await promisify(execFile)(cmd, [...args], {
		timeout: options.timeoutMs,
		killSignal: "SIGKILL",
		maxBuffer: largestCommandOutputBytes,
		...(options.signal ? { signal: options.signal } : {}),
	});
	return { stdout: String(stdout), stderr: String(stderr) };
};
