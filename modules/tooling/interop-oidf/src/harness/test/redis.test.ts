import { type Docker, DockerFailed } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { ownerLabel } from "../../orphans/orphans.ts";
import { redisImage, serverArgs, startRedis } from "./redis.ts";

/** A docker that answers each command as told, recording every call. */
function fakeDocker(answers: {
	port?: string;
	pings?: string[];
	run?: () => Promise<string>;
	rm?: () => Promise<string>;
}) {
	const calls: string[][] = [];
	const pings = [...(answers.pings ?? ["PONG"])];
	const docker: Docker = async (args) => {
		calls.push([...args]);
		if (args[0] === "run") return (answers.run ?? (async () => "c0ffee"))();
		if (args[0] === "port") return answers.port ?? "127.0.0.1:55123";
		if (args[0] === "rm") return (answers.rm ?? (async () => ""))();
		const said = pings.shift();
		if (said === undefined) throw new Error("no answer");
		return said;
	};
	return { docker, calls };
}
const nameOf = (calls: string[][]) => calls[0]?.[(calls[0]?.indexOf("--name") ?? 0) + 1] ?? "";

describe("the run's Redis server", () => {
	it("runs Redis 7 on loopback under a password of its own, fsyncing every write, named and labelled before it runs", async () => {
		const { docker, calls } = fakeDocker({ pings: ["", "PONG"] });
		const redis = await startRedis(docker, 4242);
		const run = calls[0] ?? [];
		const name = nameOf(calls);
		expect(name).toMatch(/^interop-oidf-redis-[0-9a-f]{12}$/);
		expect(run.slice(0, 7)).toEqual([
			"run",
			"-d",
			"--rm",
			"--name",
			name,
			"--label",
			`${ownerLabel}=4242`,
		]);
		expect(run.slice(7, 10)).toEqual(["-p", "127.0.0.1::6379", redisImage]);
		const password = run[run.indexOf("--requirepass") + 1] ?? "";
		expect(password).toMatch(/^[0-9a-f]{48}$/);
		expect(run.slice(10)).toEqual(serverArgs(password));
		expect(serverArgs(password).join(" ")).toContain(
			"--appendonly yes --appendfsync always --no-appendfsync-on-rewrite no --maxmemory-policy noeviction",
		);
		expect(redis.url).toBe(`redis://:${password}@127.0.0.1:55123`);
		expect(calls.filter((c) => c[0] === "exec" && c[1] === name)).toHaveLength(2);
		await redis.stop();
		expect(calls.at(-1)).toEqual(["rm", "-f", "-v", name]);
	});

	it("removes its container by name when its start's answer was lost, or it is bound to no port", async () => {
		const lost = fakeDocker({
			run: async () => Promise.reject(new DockerFailed("timeout", "run", "no answer")),
		});
		await expect(startRedis(lost.docker)).rejects.toThrow(/no answer/);
		expect(lost.calls.at(-1)).toEqual(["rm", "-f", "-v", nameOf(lost.calls)]);
		const unbound = fakeDocker({ port: "" });
		await expect(startRedis(unbound.docker)).rejects.toThrow(/no port/);
		expect(unbound.calls.at(-1)).toEqual(["rm", "-f", "-v", nameOf(unbound.calls)]);
	});

	it("takes a container gone already as stopped, and tells any other failure to remove it", async () => {
		const gone = fakeDocker({
			rm: async () => Promise.reject(new DockerFailed("absent", "rm", "no such container")),
		});
		await expect((await startRedis(gone.docker)).stop()).resolves.toBeUndefined();
		const stuck = fakeDocker({
			rm: async () => Promise.reject(new DockerFailed("failed", "rm", "busy")),
		});
		await expect((await startRedis(stuck.docker)).stop()).rejects.toThrow(/busy/);
		const both = fakeDocker({
			port: "",
			rm: async () => Promise.reject(new DockerFailed("failed", "rm", "busy")),
		});
		await expect(startRedis(both.docker)).rejects.toThrow(/was not removed/);
	});
});
