import { describe, expect, it } from "vitest";
import { differencesOf, storeOf } from "./differences.ts";

const redis = { url: "redis://:pw@127.0.0.1:6380" };

describe("the scene's store and its differences from the pattern", () => {
	it("takes Redis as generated where the harness runs one, with the operator's two statements and no store.accept-*", () => {
		const { axes, section } = storeOf({ redis });
		expect(axes).toEqual({});
		expect(section).toEqual({
			redis: { url: redis.url, replication: "none", authentication: "none" },
		});
		expect(JSON.stringify(section)).not.toContain("accept-");
	});

	it("takes the memory store on the store axis otherwise, told to accept what it cannot give", () => {
		expect(storeOf({})).toEqual({
			axes: { "@mod/store": "@mod/store" },
			section: { store: { "accept-volatile": true, "accept-unauthenticated": true } },
		});
	});

	it("names each difference for the report: the spec's, sign-up, the store as run, one sender, the published files", () => {
		const onRedis = differencesOf({ redis });
		expect(onRedis).toHaveLength(5);
		expect(onRedis[0]).toBe("The spec's: its clients and its screen.");
		expect(onRedis[2]).toContain("`redis.replication = none`");
		expect(onRedis[2]).toContain("`redis.authentication = none`");
		expect(onRedis.join("\n")).not.toContain("accept-");
		const onMemory = differencesOf({ parJarMaxLifetime: "360s", byValue: true });
		expect(onMemory[0]).toBe(
			"The spec's: its clients and its screen, PAR's `jar-max-lifetime` 360s, a JAR by value taken at a login's start.",
		);
		expect(onMemory[2]).toContain("`store.accept-unauthenticated`");
	});
});
