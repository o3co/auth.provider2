import { describe, expect, it } from "vitest";
import { systemCommand } from "../commands.ts";

describe("a program a plan runs", () => {
	it("answers what the program wrote to each stream, apart", async () => {
		const said = await systemCommand("sh", ["-c", "echo out; echo err >&2"], { timeoutMs: 10_000 });
		expect(said.stdout).toBe("out\n");
		expect(said.stderr).toBe("err\n");
	});

	it("is ended past its own time, and the call fails", async () => {
		const started = Date.now();
		await expect(systemCommand("sleep", ["30"], { timeoutMs: 100 })).rejects.toMatchObject({
			killed: true,
			signal: "SIGKILL",
		});
		expect(Date.now() - started).toBeLessThan(10_000);
	});

	it("is ended where the plan's deadline aborts, and the call fails", async () => {
		const deadline = new AbortController();
		const ran = systemCommand("sleep", ["30"], { timeoutMs: 60_000, signal: deadline.signal });
		setTimeout(() => deadline.abort(), 100);
		await expect(ran).rejects.toMatchObject({ name: "AbortError" });
	});
});
