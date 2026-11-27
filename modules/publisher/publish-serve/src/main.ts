#!/usr/bin/env node
import { publishServe } from "./serve.ts";

const run = await publishServe(process.argv.slice(2));
for (const line of run.lines) (run.code === 0 ? process.stdout : process.stderr).write(`${line}\n`);
if (run.code !== 0) process.exitCode = run.code;
else {
	const stop = () => void run.serving?.close();
	process.once("SIGTERM", stop);
	process.once("SIGINT", stop);
}
