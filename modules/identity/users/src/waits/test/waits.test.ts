import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Verified } from "../../contract.ts";
import { identifierWaits, type WaitRules } from "../waits.ts";

const rules: WaitRules = { after: 2, firstMs: 1000, longestMs: 4000, forgetMs: 60_000 };
const none: Verified = { kind: "none" };
const user: Verified = { kind: "user", user: { subject: "s-alice", attributes: {} } };

/** Waits over a clock the test moves, recording each pause asked for and passing that time. */
function waitsAt(given: WaitRules = rules) {
	const clock = { at: 0 };
	const paused: number[] = [];
	const waits = identifierWaits(given, {
		now: () => clock.at,
		pause: async (ms) => {
			paused.push(ms);
			clock.at += ms;
		},
	});
	return { waits, paused, clock };
}

describe("identifierWaits", () => {
	it("lets the first failures through at once, then doubles the wait up to the longest", async () => {
		const { waits, paused } = waitsAt();
		for (let i = 0; i < 6; i++) await waits.run("alice", async () => none);
		expect(paused).toEqual([1000, 2000, 4000, 4000]);
	});

	it("counts each identifier apart, a known one and an unknown one alike", async () => {
		const { waits, paused } = waitsAt();
		for (let i = 0; i < 3; i++) await waits.run("alice", async () => none);
		await waits.run("nobody", async () => none);
		expect(paused).toEqual([1000]);
	});

	it("ends a run on a user found, and leaves it on a throw", async () => {
		const { waits, paused } = waitsAt();
		await waits.run("alice", async () => none);
		await waits.run("alice", async () => none);
		await expect(
			waits.run("alice", async () => {
				throw new Unavailable("users");
			}),
		).rejects.toThrow(Unavailable);
		expect(await waits.run("alice", async () => user)).toBe(user);
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000, 1000]);
	});

	it("forgets a run left quiet for the forget time", async () => {
		const { waits, paused, clock } = waitsAt();
		for (let i = 0; i < 3; i++) await waits.run("alice", async () => none);
		clock.at += rules.forgetMs;
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});

	it("checks one identifier one at a time, each after its wait, so checks sent at once wait in turn", async () => {
		const { waits, paused } = waitsAt();
		const order: number[] = [];
		await Promise.all(
			[0, 1, 2, 3].map((n) =>
				waits.run("alice", async () => {
					order.push(n);
					return none;
				}),
			),
		);
		expect(order).toEqual([0, 1, 2, 3]);
		expect(paused).toEqual([1000, 2000]);
	});

	it("waits for no one where after is past every run", async () => {
		const { waits, paused } = waitsAt({ ...rules, after: 1000 });
		for (let i = 0; i < 10; i++) await waits.run("alice", async () => none);
		expect(paused).toEqual([]);
	});
});

it("lets an idle identifier go to make room past the capacity, so memory stays bounded", async () => {
	const clock = { at: 0 };
	const paused: number[] = [];
	const timing = {
		now: () => clock.at,
		pause: async (ms: number) => {
			paused.push(ms);
		},
	};
	const waits = identifierWaits(rules, timing, 1);
	for (let i = 0; i < 2; i++) await waits.run("alice", async () => none);
	await waits.run("bob", async () => none);
	await waits.run("alice", async () => none);
	expect(paused).toEqual([]);
});
