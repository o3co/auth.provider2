import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { runA, runAms } from "./run.ts";

/**
 * Run A, recorded: the suite at its pin against the scene on Redis, every module of the plan. Docker,
 * `git`, `openssl` and Python 3 on the path, and the network for the suite's source and images. Run by
 * hand (`pnpm run:a`), never by `pnpm check`; `OIDF_RUN_DIR` names where its record goes. The run
 * starts no module past its own deadline, well inside this test's time, so its stop is always awaited.
 */
it("runs every module of run A's plan as its expected results say", {
	timeout: runAms + 60 * 60_000,
}, async ({ signal }) => {
	const out = process.env.OIDF_RUN_DIR ?? join(tmpdir(), `oidf-run-a-${Date.now()}`);
	const ran = await runA(out, AbortSignal.any([signal, AbortSignal.timeout(runAms)]));
	console.log(`run A's report: ${ran.report}`);
	expect(ran.passed, `run A failed; its report: ${ran.report}`).toBe(true);
});
