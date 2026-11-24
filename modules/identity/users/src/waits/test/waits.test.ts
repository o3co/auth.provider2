import { isUnavailable, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Verified } from "../../contract.ts";
import { identifierWaits, queueBound, type WaitRules } from "../waits.ts";

const rules: WaitRules = { after: 2, firstMs: 1000, longestMs: 4000, forgetMs: 60_000 };
const none: Verified = { kind: "none" };
const user: Verified = { kind: "user", user: { subject: "s-alice", attributes: {} } };

/** Waits over a clock the test moves, recording each pause asked for and passing that time. */
function waitsAt(given: WaitRules = rules, capacity?: number) {
	const clock = { at: 0 };
	const paused: number[] = [];
	const timing = {
		now: () => clock.at,
		pause: async (ms: number) => {
			paused.push(ms);
			clock.at += ms;
		},
	};
	const waits =
		capacity === undefined
			? identifierWaits(given, timing)
			: identifierWaits(given, timing, capacity);
	return { waits, paused, clock };
}

/** A check held until the test lets it answer. */
function held() {
	let answer: (verified: Verified) => void = () => {};
	const check = () =>
		new Promise<Verified>((resolve) => {
			answer = resolve;
		});
	return { check, answer: (verified: Verified) => answer(verified) };
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

	it("keeps the failures past a user found and past a throw, so a wait tells nothing of who exists", async () => {
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
		expect(paused).toEqual([1000, 1000, 1000]);
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
			Array.from({ length: queueBound }, (_, n) =>
				waits.run("alice", async () => {
					order.push(n);
					return none;
				}),
			),
		);
		expect(order).toEqual(Array.from({ length: queueBound }, (_, n) => n));
		expect(paused).toEqual([1000, 2000]);
	});

	it("refuses a check past the queue's bound as unavailable, unchecked and uncounted, known or not", async () => {
		const { waits, paused } = waitsAt();
		for (const identifier of ["alice", "nobody"]) {
			const first = held();
			const queued = [waits.run(identifier, first.check)];
			for (let n = 1; n < queueBound; n++) queued.push(waits.run(identifier, async () => none));
			let asked = false;
			const over = waits.run(identifier, async () => {
				asked = true;
				return none;
			});
			await expect(over).rejects.toSatisfy(isUnavailable);
			expect(asked).toBe(false);
			first.answer(none);
			await Promise.all(queued);
		}
		// Each identifier counted its own checks alone: the refused one added no failure.
		expect(paused).toEqual([1000, 2000, 1000, 2000]);
	});

	it("bounds a check's wait by the queue: at most the bound times the longest wait, whatever was sent before", async () => {
		const { waits, paused } = waitsAt({ ...rules, after: 0 });
		for (let i = 0; i < 10; i++) await waits.run("alice", async () => none);
		paused.length = 0;
		const sent = Array.from({ length: 100 }, () =>
			waits.run("alice", async () => none).catch(() => "refused"),
		);
		const answers = await Promise.all(sent);
		expect(answers.filter((a) => a !== "refused")).toHaveLength(queueBound);
		expect(paused.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(queueBound * rules.longestMs);
	});

	it("waits for no one where after is past every run", async () => {
		const { waits, paused } = waitsAt({ ...rules, after: 1000 });
		for (let i = 0; i < 10; i++) await waits.run("alice", async () => none);
		expect(paused).toEqual([]);
	});
});

describe("identifierWaits at its capacity", () => {
	it("lets the run with the fewest failures go to make room", async () => {
		const { waits, paused } = waitsAt({ ...rules, after: 1 }, 2);
		for (let i = 0; i < 2; i++) await waits.run("alice", async () => none);
		await waits.run("bob", async () => none);
		// Full: carol takes bob's place, who failed fewer times; alice's run stays.
		await waits.run("carol", async () => none);
		await waits.run("alice", async () => none);
		await waits.run("bob", async () => none);
		expect(paused).toEqual([1000, 2000]);
	});

	it("lets a run past its forget time go before one that failed fewer times", async () => {
		const { waits, paused, clock } = waitsAt({ ...rules, after: 1 }, 2);
		for (let i = 0; i < 3; i++) await waits.run("alice", async () => none);
		clock.at = 40_000;
		await waits.run("bob", async () => none);
		clock.at = 64_000;
		// Alice's run is past its forget time; bob's, with one failure, stays and waits.
		await waits.run("carol", async () => none);
		await waits.run("bob", async () => none);
		expect(paused).toEqual([1000, 2000, 1000]);
	});

	it("refuses a new identifier as unavailable where every one held has a check under way", async () => {
		const { waits } = waitsAt(rules, 1);
		const first = held();
		const running = waits.run("alice", first.check);
		let asked = false;
		await expect(
			waits.run("bob", async () => {
				asked = true;
				return none;
			}),
		).rejects.toSatisfy(isUnavailable);
		expect(asked).toBe(false);
		first.answer(none);
		await running;
		expect(await waits.run("bob", async () => none)).toEqual(none);
	});
});
