/** The scene's store, and its differences from the pattern as a run's report names them. */
import { redisConfig } from "@mod/redis/testing";
import { storeConfig } from "@mod/store/testing";

/** The Redis server a scene's Core takes, as the harness ran it: its URL, password in it. */
export interface RedisServer {
	readonly url: string;
}

/** What the store differs by: the scene's spec, as far as it changes the pattern. */
export interface StoreSpec {
	readonly redis?: RedisServer;
	readonly parJarMaxLifetime?: string;
	readonly byValue?: true;
}

/**
 * The Core's store: Redis as generated, with the operator's two statements its one server needs, where
 * the harness runs one; else the memory store on the store axis, told to accept what it cannot give.
 */
export function storeOf(spec: StoreSpec): {
	readonly axes: Readonly<Record<string, string>>;
	readonly section: Readonly<Record<string, unknown>>;
} {
	return spec.redis === undefined
		? {
				axes: { "@mod/store": "@mod/store" },
				section: storeConfig({ "accept-unauthenticated": true }),
			}
		: {
				axes: {},
				section: redisConfig({ url: spec.redis.url, replication: "none", authentication: "none" }),
			};
}

/** The pattern's differences in a scene of this spec, each a line of a run's report. */
export function differencesOf(spec: StoreSpec): readonly string[] {
	const asked = [
		"its clients and its screen",
		...(spec.parJarMaxLifetime === undefined
			? []
			: [`PAR's \`jar-max-lifetime\` ${spec.parJarMaxLifetime}`]),
		...(spec.byValue ? ["a JAR by value taken at a login's start"] : []),
	];
	return [
		`The spec's: ${asked.join(", ")}.`,
		"`sign-up` added.",
		spec.redis === undefined
			? "The memory store (`store.accept-volatile` and `store.accept-unauthenticated`): redis's fake boots the module and serves no request."
			: "Redis 7, one server the harness runs on loopback, under its password and an fsync on every write, with the operator's two statements: `redis.replication = none` (one server, no failover) and `redis.authentication = none` (no Redis store tells a write made outside the provider apart), each warned at every boot.",
		"One sender (RFC 5737's `192.0.2.10`): every client reaches the front from loopback, which the Front takes for its trusted proxy.",
		"The harness answering the published files: the publisher is the operator's and trusted.",
	];
}
