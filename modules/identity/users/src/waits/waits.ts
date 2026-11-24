import type { Verified } from "../contract.ts";

/** How failed checks of one identifier make its next checks wait. */
export interface WaitRules {
	/** Failures in a row an identifier takes before its checks wait. */
	readonly after: number;
	/** The first wait; each further failure doubles it. */
	readonly firstMs: number;
	/** The longest wait. */
	readonly longestMs: number;
	/** A run of failures left quiet this long is forgotten. */
	readonly forgetMs: number;
}

/** The time the waits read and spend: a clock, and a pause of some milliseconds. */
export interface Timing {
	readonly now: () => number;
	readonly pause: (ms: number) => Promise<void>;
}

export interface Waits {
	/**
	 * Runs `check` for the identifier after its wait, one check of an identifier at a time. A user
	 * found ends its run of failures, none adds to it, and a throw leaves it as it was.
	 */
	run(identifier: string, check: () => Promise<Verified>): Promise<Verified>;
}

interface Run {
	failures: number;
	lastFailureAt: number;
	/** Checks of the identifier queued or under way. */
	queued: number;
	tail: Promise<unknown>;
}

/** A fixed guard on the identifiers held at once, so unknown identifiers cannot fill memory. */
const defaultCapacity = 100_000;

/** Waits per identifier, held in this process. */
export function identifierWaits(
	rules: WaitRules,
	timing: Timing,
	capacity = defaultCapacity,
): Waits {
	const runs = new Map<string, Run>();
	const waitOf = (run: Run) => {
		if (timing.now() - run.lastFailureAt >= rules.forgetMs) run.failures = 0;
		const past = run.failures - rules.after;
		return past < 0 ? 0 : Math.min(rules.firstMs * 2 ** past, rules.longestMs);
	};
	const runOf = (identifier: string) => {
		const held = runs.get(identifier);
		if (held) return held;
		if (runs.size >= capacity) {
			for (const [held, run] of runs) {
				if (run.queued === 0) {
					runs.delete(held);
					break;
				}
			}
		}
		const run: Run = { failures: 0, lastFailureAt: 0, queued: 0, tail: Promise.resolve() };
		runs.set(identifier, run);
		return run;
	};
	return {
		run: async (identifier, check) => {
			const run = runOf(identifier);
			run.queued += 1;
			const turn = run.tail.then(async () => {
				const ms = waitOf(run);
				if (ms > 0) await timing.pause(ms);
				const answer = await check();
				if (answer.kind === "user") {
					run.failures = 0;
				} else {
					run.failures += 1;
					run.lastFailureAt = timing.now();
				}
				return answer;
			});
			run.tail = turn.catch(() => undefined);
			try {
				return await turn;
			} finally {
				run.queued -= 1;
				if (run.queued === 0 && run.failures === 0) runs.delete(identifier);
			}
		},
	};
}
