import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Docker } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { reclaimOrphans } from "../orphans.ts";

/** A docker client that answers as `answer` says, keeping each call; one it does not know answers nothing. */
function dockers(answer: (args: readonly string[]) => string = () => "") {
	const calls: { args: readonly string[]; within: number; merged: boolean }[] = [];
	const docker: Docker = async (args, within, told) => {
		calls.push({ args, within, merged: told?.merged ?? false });
		return answer(args);
	};
	return { docker, calls };
}

describe("the suites a run left behind", () => {
	it("takes down the suites whose owner is gone, keeping their logs, and leaves a live owner's", async () => {
		const logs = await mkdtemp(join(tmpdir(), "reclaimed-"));
		const { docker, calls } = dockers((args) => {
			if (args[0] === "ps")
				return [
					"a1\t111\to3co-oidf-live\tlive-server-1",
					"b1\t222\to3co-oidf-gone\tgone-server-1",
					"b2\t222\to3co-oidf-gone\tgone-mongodb-1",
				].join("\n");
			if (args[0] === "logs") return `log of ${args.at(-1)}`;
			if (args[0] === "network" && args[1] === "ls") return "n1";
			return "";
		});
		const reclaimed = await reclaimOrphans(docker, logs, (pid) => pid === 111);
		expect(reclaimed).toEqual(["o3co-oidf-gone"]);
		const removed = calls.filter((c) => c.args[0] === "rm").flatMap((c) => c.args);
		expect(removed).toEqual(expect.arrayContaining(["b1", "b2"]));
		expect(removed).not.toContain("a1");
		expect(calls.some((c) => c.args.join(" ") === "network rm n1")).toBe(true);
		expect((await readdir(logs)).sort()).toEqual([
			"o3co-oidf-gone-gone-mongodb-1.log",
			"o3co-oidf-gone-gone-server-1.log",
		]);
		expect(await readFile(join(logs, "o3co-oidf-gone-gone-server-1.log"), "utf8")).toBe(
			"log of b1",
		);
		for (const c of calls) expect(c.within).toBeGreaterThan(0);
	});

	it("keeps what each container wrote to either stream, asking the client for both", async () => {
		const logs = await mkdtemp(join(tmpdir(), "reclaimed-"));
		const { docker, calls } = dockers((args) => {
			if (args[0] === "ps") return "b1\t222\to3co-oidf-gone\tgone-server-1";
			// The client's answer with both streams merged, as `merged` asks it.
			if (args[0] === "logs") return "started\njava.lang.OutOfMemoryError";
			return "";
		});
		await reclaimOrphans(docker, logs, () => false);
		expect(calls.filter((c) => c.args[0] === "logs").map((c) => c.merged)).toEqual([true]);
		expect(await readFile(join(logs, "o3co-oidf-gone-gone-server-1.log"), "utf8")).toBe(
			"started\njava.lang.OutOfMemoryError",
		);
	});

	it("takes the suite down though its logs' directory cannot be made, and then tells it", async () => {
		const parent = await mkdtemp(join(tmpdir(), "reclaimed-"));
		// A file where the directory's parent should be: the directory cannot be made.
		await writeFile(join(parent, "full"), "");
		const { docker, calls } = dockers((args) => {
			if (args[0] === "ps") return "b1\t222\to3co-oidf-gone\tgone-server-1";
			if (args[0] === "network" && args[1] === "ls") return "n1";
			return "";
		});
		await expect(
			reclaimOrphans(docker, join(parent, "full", "reclaimed"), () => false),
		).rejects.toThrow("could not be taken down");
		expect(calls.some((c) => c.args[0] === "rm" && c.args.includes("b1"))).toBe(true);
		expect(calls.some((c) => c.args.join(" ") === "network rm n1")).toBe(true);
	});

	it("tries every step though some fail, every network too, and tells each failure after", async () => {
		const { docker, calls } = dockers((args) => {
			if (args[0] === "ps")
				return [
					"b1\t222\to3co-oidf-one\tone-server-1",
					"c1\t333\to3co-oidf-two\ttwo-server-1",
				].join("\n");
			if (args[0] === "rm" && args.includes("b1")) throw new Error("rm b1 failed");
			if (args[0] === "network" && args[1] === "ls")
				return args.at(-1)?.endsWith("o3co-oidf-one") ? "n1\nn2" : "n3";
			if (args[0] === "network" && args[1] === "rm" && args[2] === "n1")
				throw new Error("network rm n1 failed");
			return "";
		});
		const error = await reclaimOrphans(docker, undefined, () => false).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(AggregateError);
		expect((error as AggregateError).errors.map(String)).toEqual([
			"Error: rm b1 failed",
			"Error: network rm n1 failed",
		]);
		const removed = calls.filter((c) => c.args[0] === "network" && c.args[1] === "rm");
		expect(removed.map((c) => c.args[2])).toEqual(["n1", "n2", "n3"]);
		expect(calls.some((c) => c.args[0] === "rm" && c.args.includes("c1"))).toBe(true);
	});
});
