/**
 * keys-kms as an app composes it, in a process of its own the test holds by Node's permission model:
 * it boots on the section given (its first argument, JSON), signs with the authority's key, and
 * signs again each time a line comes on its standard input. Each outcome is one JSON line on its
 * standard output: `{"signed":n}`, or `{"failed":…}` with the error's name, code, message, cause
 * and, for a refused boot, its refusals; and at its end `{"logged":[…]}`, keys-kms' own log lines.
 */
import { createInterface } from "node:readline";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import keysKmsModule from "../../src/module.ts";

const told = (line: unknown) => process.stdout.write(`${JSON.stringify(line)}\n`);
const failed = (error: unknown) => {
	const { name, code, message } = (error ?? {}) as {
		name?: string;
		code?: string;
		message?: string;
	};
	// What the error carries, and its cause's, where the SDK wraps one.
	const { cause, refusals } = (error ?? {}) as {
		cause?: { code?: string; message?: string };
		refusals?: readonly unknown[];
	};
	told({
		failed: {
			name,
			code,
			message,
			...(cause && { cause: { code: cause.code, message: cause.message } }),
			...(refusals && { refusals }),
		},
	});
};

const section = JSON.parse(process.argv[2] ?? "{}");
const recorded = recordingLog();
let signed = 0;
try {
	const app = await assemble({
		modules: [keysModule, keysKmsModule],
		config: { ...kernelConfig(), ...keysConfig(), "keys-kms": section },
		runtime: quietRuntime({ log: recorded.log }),
	});
	const k = app.get(keys);
	const sign = async () => {
		const done = await k.sign(k.prepare("authority", "JWT"), new TextEncoder().encode("{}"));
		if (done.kind !== "signed") throw new Error(`not signed: ${done.kind}`);
		signed += 1;
		told({ signed });
	};
	await sign().catch(failed);
	for await (const _ of createInterface({ input: process.stdin })) await sign().catch(failed);
	await app.stop();
} catch (error) {
	failed(error);
}
told({ logged: recorded.lines().filter((line) => line.event.startsWith("keys-kms.")) });
