#!/usr/bin/env node
import { signRegistry } from "./sign.ts";

const run = await signRegistry(process.argv.slice(2));
for (const line of run.lines) (run.code === 0 ? process.stdout : process.stderr).write(`${line}\n`);
process.exitCode = run.code;
