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

/** A check's answer, held as a failure until what it was part of is settled. */
export interface Pending {
	readonly answer: Verified;
	/** Once: a user found stops counting as a failure where `passed`; nothing else changes. */
	settle(passed: boolean): void;
}

export interface Waits {
	/**
	 * Runs `check` for the identifier after its wait, one check of an identifier at a time. None
	 * found adds a failure; a user found and a throw leave the run as it was. A check past the
	 * identifier's queue, or a new identifier where none held can make room, is Unavailable,
	 * unchecked and uncounted.
	 */
	run(identifier: string, check: () => Promise<Verified>): Promise<Verified>;
	/**
	 * As `run`, for a check that is one part of something larger: a user found adds a failure too,
	 * taken back only where `settle(true)` comes. One never settled stays a failure.
	 */
	runPending(identifier: string, check: () => Promise<Verified>): Promise<Pending>;
}

/**
 * The most failed checks of one identifier in any window of `forgetMs`, in this process: two failures
 * that close come in one run, its first check's wait maybe before the window, each later one's in
 * it; one more for a run forgotten at the window's very edge.
 */
export function failedChecksWithin(rules: WaitRules): number {
	const window = rules.forgetMs;
	// The first check, then those its run lets through at once.
	let count = Math.max(rules.after, 1);
	let spent = 0;
	for (let past = Math.max(rules.after, 1) - rules.after; ; past++) {
		const wait = Math.min(rules.firstMs * 2 ** past, rules.longestMs);
		if (wait === rules.longestMs) {
			count += Math.floor((window - spent) / wait);
			break;
		}
		if (spent + wait > window) break;
		spent += wait;
		count++;
	}
	return count + 1;
}

interface Run {
	failures: number;
	lastFailureAt: number;
	/** Checks of the identifier queued or under way. */
	queued: number;
	tail: Promise<unknown>;
	/** Counts each forgetting, so a pending check settled after one takes back nothing of the run after it. */
	forgotten: number;
}

/** The checks of one identifier held at once, the one under way among them: a fixed guard. */
export const queueBound = 4;

/** Waits per identifier, held in this process. */
export function identifierWaits(
	rules: WaitRules,
	timing: Timing,
	/** The identifiers held at once, so unknown identifiers cannot fill memory. */
	capacity: number,
): Waits {
	const runs = new Map<string, Run>();
	const quiet = (run: Run, at: number) => at - run.lastFailureAt >= rules.forgetMs;
	const waitOf = (run: Run) => {
		if (run.failures > 0 && quiet(run, timing.now())) {
			run.failures = 0;
			run.forgotten += 1;
		}
		const past = run.failures - rules.after;
		return past < 0 ? 0 : Math.min(rules.firstMs * 2 ** past, rules.longestMs);
	};
	/** An idle run past its forget time; none where every run is under way or holds failures not forgotten. */
	const releasable = () => {
		const at = timing.now();
		for (const [identifier, run] of runs) if (run.queued === 0 && quiet(run, at)) return identifier;
		return undefined;
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
		const run: Run = {
			failures: 0,
			lastFailureAt: 0,
			queued: 0,
			tail: Promise.resolve(),
			forgotten: 0,
		};
		runs.set(identifier, run);
		return run;
	};
	const released = (identifier: string, run: Run) => {
		if (run.queued === 0 && run.failures === 0 && runs.get(identifier) === run)
			runs.delete(identifier);
	};
	/** The check after its wait; `failed` says which answers add a failure. */
	const turnOf = async (
		identifier: string,
		check: () => Promise<Verified>,
		failed: (answer: Verified) => boolean,
	) => {
		const run = admitted(identifier);
		run.queued += 1;
		const turn = run.tail.then(async () => {
			const ms = waitOf(run);
			if (ms > 0) await timing.pause(ms);
			const answer = await check();
			if (failed(answer)) {
				run.failures += 1;
				run.lastFailureAt = timing.now();
			}
			return { answer, forgotten: run.forgotten };
		});
		run.tail = turn.catch(() => undefined);
		try {
			return { run, ...(await turn) };
		} finally {
			run.queued -= 1;
			released(identifier, run);
		}
	};
	return {
		run: async (identifier, check) =>
			(await turnOf(identifier, check, (answer) => answer.kind !== "user")).answer,
		runPending: async (identifier, check) => {
			const { run, answer, forgotten } = await turnOf(identifier, check, () => true);
			let settled = false;
			return {
				answer,
				settle: (passed) => {
					if (settled) return;
					settled = true;
					// A run forgotten since holds failures of later checks only.
					if (!passed || answer.kind !== "user" || run.forgotten !== forgotten) return;
					run.failures = Math.max(run.failures - 1, 0);
					released(identifier, run);
				},
			};
		},
	};
}
