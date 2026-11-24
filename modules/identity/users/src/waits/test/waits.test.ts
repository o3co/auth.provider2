import { isUnavailable, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Verified } from "../../contract.ts";
import { failedChecksWithin, identifierWaits, queueBound, type WaitRules } from "../waits.ts";

const rules: WaitRules = { after: 2, firstMs: 1000, longestMs: 4000, forgetMs: 60_000 };
const none: Verified = { kind: "none" };
const user: Verified = { kind: "user", user: { subject: "s-alice", attributes: {} } };

/** Waits over a clock the test moves, recording each pause asked for and passing that time. */
function waitsAt(given: WaitRules = rules, capacity = 100_000) {
	const clock = { at: 0 };
	const paused: number[] = [];
	const timing = {
		now: () => clock.at,
		pause: async (ms: number) => {
			paused.push(ms);
			clock.at += ms;
		},
	};
	const waits = identifierWaits(given, timing, capacity);
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

describe("a pending check", () => {
	it("counts a user found as a failure until settled passed, and only once", async () => {
		const { waits, paused } = waitsAt();
		await waits.run("alice", async () => none);
		const passing = await waits.runPending("alice", async () => user);
		expect(passing.answer).toBe(user);
		// Two failures now: the third check is let through, the fourth would wait.
		passing.settle(true);
		passing.settle(true);
		await waits.run("alice", async () => none);
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});

	it("keeps a user found as a failure where settled not passed, or never settled", async () => {
		const { waits, paused } = waitsAt();
		const failing = await waits.runPending("alice", async () => user);
		failing.settle(false);
		failing.settle(true);
		await waits.runPending("alice", async () => user);
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});

	it("keeps none found a failure, settled passed or not", async () => {
		const { waits, paused } = waitsAt();
		for (let i = 0; i < 2; i++) (await waits.runPending("alice", async () => none)).settle(true);
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});
});

describe("a pending check across a forgetting", () => {
	it("takes back nothing of the failures after its run was forgotten", async () => {
		const { waits, paused, clock } = waitsAt({ ...rules, after: 1 });
		const early = await waits.runPending("alice", async () => user);
		clock.at += rules.forgetMs;
		await waits.run("alice", async () => none);
		early.settle(true);
		// The later failure stands: the next check waits.
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});
});

describe("a pending check of a run let go", () => {
	it("takes back nothing of the run made after its own was let go", async () => {
		const { waits, paused, clock } = waitsAt({ ...rules, after: 1 }, 1);
		const early = await waits.runPending("alice", async () => user);
		clock.at += rules.forgetMs;
		// Alice's run is past its forget time: bob takes its place, then alice's anew.
		await waits.run("bob", async () => user);
		await waits.run("alice", async () => none);
		early.settle(true);
		await waits.run("alice", async () => none);
		expect(paused).toEqual([1000]);
	});
});

describe("failedChecksWithin", () => {
	it("answers the failed checks the defaults allow in a quarter hour: three at once, five doubling, then one each half minute, and one more", () => {
		const defaults = { after: 3, firstMs: 1000, longestMs: 30_000, forgetMs: 900_000 };
		expect(failedChecksWithin(defaults)).toBe(3 + 5 + 28 + 1);
	});

	it("bounds what a sender gets, failing at once whenever let through, in any window of the forget time", async () => {
		for (const given of [rules, { ...rules, after: 0 }, { ...rules, after: 7, firstMs: 3000 }]) {
			const { waits, clock } = waitsAt(given);
			const at: number[] = [];
			while (clock.at < 3 * given.forgetMs) {
				await waits.run("alice", async () => none);
				at.push(clock.at);
			}
			const most = Math.max(
				...at.map((start) => at.filter((t) => t >= start && t <= start + given.forgetMs).length),
			);
			expect(most).toBeLessThanOrEqual(failedChecksWithin(given));
			expect(most).toBeGreaterThanOrEqual(failedChecksWithin(given) - 2);
		}
	});

	it("counts a run of no waits without stepping through it", () => {
		expect(failedChecksWithin({ ...rules, after: 1_000_000_000 })).toBeGreaterThan(1_000_000_000);
	});
});

describe("identifierWaits at its capacity", () => {
	it("refuses a new identifier as unavailable where every run held keeps failures not forgotten, so none is reset", async () => {
		const { waits, paused } = waitsAt({ ...rules, after: 1 }, 2);
		for (let i = 0; i < 2; i++) await waits.run("alice", async () => none);
		await waits.run("bob", async () => none);
		await expect(waits.run("carol", async () => none)).rejects.toSatisfy(isUnavailable);
		await waits.run("alice", async () => none);
		await waits.run("bob", async () => none);
		expect(paused).toEqual([1000, 2000, 1000]);
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
		// Alice's check found her and left no failure: her run is let go, and bob is held.
		first.answer(user);
		await running;
		expect(await waits.run("bob", async () => none)).toEqual(none);
	});
});
