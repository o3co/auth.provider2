import { randomBytes } from "node:crypto";
import {
	type Docker,
	DockerFailed,
	dockerWithin,
	docker as systemDocker,
} from "@mod/docker-client";
import { ownerLabel } from "../../orphans/orphans.ts";

/** The image the recorded run's store runs on: Redis 7, as the store's own tests run it. */
export const redisImage = "redis:7.4-alpine";

/** How long the server may take to answer once its container runs. */
const readyMs = 30_000;

/** A Redis server the harness runs for a run: its URL (a password in it), and its stop. */
export interface RunningRedis {
	readonly url: string;
	stop(): Promise<void>;
}

/**
 * The server's settings: a password of the run's own, an fsync on every write (durable, as the store
 * reads `appendonly`, `appendfsync` and `no-appendfsync-on-rewrite`), and no eviction.
 */
export const serverArgs = (password: string) => [
	"redis-server",
	"--requirepass",
	password,
	"--appendonly",
	"yes",
	"--appendfsync",
	"always",
	"--no-appendfsync-on-rewrite",
	"no",
	"--maxmemory-policy",
	"noeviction",
];

/**
 * Runs Redis in a container on loopback at a port Docker picks, once it answers its password. The
 * container is named before it runs and carries `orphans`' owner label, so a start whose answer was
 * lost is removed by its name, and a run killed before its stop leaves it for the next suite's start
 * to take down. A start that fails removes it; the stop removes it and its volume, one gone already
 * being stopped.
 */
export async function startRedis(
	docker: Docker = systemDocker,
	owner: number = process.pid,
): Promise<RunningRedis> {
	const password = randomBytes(24).toString("hex");
	const name = `interop-oidf-redis-${randomBytes(6).toString("hex")}`;
	const stop = async () => {
		await docker(["rm", "-f", "-v", name], dockerWithin.control).catch((failed: unknown) => {
			if (!(failed instanceof DockerFailed && failed.kind === "absent")) throw failed;
		});
	};
	try {
		await docker(
			[
				...["run", "-d", "--rm", "--name", name, "--label", `${ownerLabel}=${owner}`],
				...["-p", "127.0.0.1::6379", redisImage, ...serverArgs(password)],
			],
			dockerWithin.run,
		);
		const bound = await docker(["port", name, "6379/tcp"], dockerWithin.control);
		const port = /:(\d+)\s*$/m.exec(bound)?.[1];
		if (port === undefined) throw new Error(`Redis is bound to no port: ${bound}`);
		const ping = ["exec", name, "redis-cli", "-a", password, "--no-auth-warning", "ping"];
		for (const end = Date.now() + readyMs; ; ) {
			const said = await docker(ping, dockerWithin.control).catch(() => "");
			if (said === "PONG") break;
			if (Date.now() > end) throw new Error(`Redis did not answer within ${readyMs} ms`);
			await new Promise((r) => setTimeout(r, 200));
		}
		return { url: `redis://:${password}@127.0.0.1:${port}`, stop };
	} catch (failed) {
		const removed = await stop().then(
			() => undefined,
			(e: unknown) => e,
		);
		throw removed === undefined
			? failed
			: new AggregateError([failed, removed], "Redis did not start, and was not removed");
	}
}
