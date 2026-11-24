import { Unavailable } from "@mod/kernel";
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
	 * Runs `check` for the identifier after its wait, one check of an identifier at a time. None
	 * found adds a failure; a user found and a throw leave the run as it was. A check past the
	 * identifier's queue, or a new identifier where none held can make room, is Unavailable,
	 * unchecked and uncounted.
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

/** The checks of one identifier held at once, the one under way among them: a fixed guard. */
export const queueBound = 4;
/** A fixed guard on the identifiers held at once, so unknown identifiers cannot fill memory. */
const defaultCapacity = 100_000;

/** Waits per identifier, held in this process. */
export function identifierWaits(
	rules: WaitRules,
	timing: Timing,
	capacity = defaultCapacity,
): Waits {
	const runs = new Map<string, Run>();
	const quiet = (run: Run, at: number) => at - run.lastFailureAt >= rules.forgetMs;
	const waitOf = (run: Run) => {
		if (quiet(run, timing.now())) run.failures = 0;
		const past = run.failures - rules.after;
		return past < 0 ? 0 : Math.min(rules.firstMs * 2 ** past, rules.longestMs);
	};
	/** An idle run past its forget time first, else the idle one with the fewest failures; none where every run is under way. */
	const releasable = () => {
		const at = timing.now();
		let fewest: [string, Run] | undefined;
		for (const held of runs) {
			const [, run] = held;
			if (run.queued > 0) continue;
			if (quiet(run, at)) return held[0];
			if (!fewest || run.failures < fewest[1].failures) fewest = held;
		}
		return fewest?.[0];
	};
	const admitted = (identifier: string) => {
		const held = runs.get(identifier);
		if (held) {
			if (held.queued >= queueBound) throw new Unavailable("users");
			return held;
		}
		if (runs.size >= capacity) {
			const released = releasable();
			if (released === undefined) throw new Unavailable("users");
			runs.delete(released);
		}
		const run: Run = { failures: 0, lastFailureAt: 0, queued: 0, tail: Promise.resolve() };
		runs.set(identifier, run);
		return run;
	};
	return {
		run: async (identifier, check) => {
			const run = admitted(identifier);
			run.queued += 1;
			const turn = run.tail.then(async () => {
				const ms = waitOf(run);
				if (ms > 0) await timing.pause(ms);
				const answer = await check();
				if (answer.kind !== "user") {
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
