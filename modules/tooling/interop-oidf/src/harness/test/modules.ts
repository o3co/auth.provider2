import type { ModuleRun } from "../../results/test/results.ts";
import type { Suite } from "../../suite/suite.ts";

/** How long a module may run, how often it is asked after, and how long a stopped one may take to end. */
export interface Timing {
	readonly moduleMs: number;
	readonly pollMs: number;
	readonly stopMs: number;
	/** How long the suite takes to write a module's last entries once it says INTERRUPTED. */
	readonly settleMs: number;
	readonly now?: () => number;
	readonly sleep?: (ms: number) => Promise<void>;
}

export const timingA: Timing = {
	moduleMs: 8 * 60_000,
	pollMs: 2000,
	stopMs: 60_000,
	settleMs: 2000,
};

const finished = (status: unknown) => status === "FINISHED" || status === "INTERRUPTED";
type Info = { readonly status?: string; readonly result?: string };

/**
 * Runs each module of a plan in turn, judged under the plan's variant (never its info's: the suite adds
 * its defaulted parameters there), each module's info and log given to `record`. A module not done
 * in its time is stopped (`DELETE`), its stop awaited, and kept as timed out, failing it; one the
 * suite would not start is kept as not started. A failed ask is asked again until the module's time.
 * A signal aborted starts no module more, and ends a module's wait at once: kept as aborted, it is
 * the suite's stop's to take down, the suite's calls ending with the signal.
 */
export async function runModules(
	suite: Pick<Suite, "call" | "api">,
	plan: {
		readonly id: string;
		readonly variant: Readonly<Record<string, string>>;
		readonly tests: readonly string[];
	},
	timing: Timing,
	record: (test: string, info: unknown, log: unknown) => Promise<void>,
	signal?: AbortSignal,
): Promise<ModuleRun[]> {
	const now = timing.now ?? Date.now;
	const sleep = timing.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const variant = encodeURIComponent(JSON.stringify(plan.variant));
	const infoOf = (id: string) =>
		suite.api(`api/info/${id}`).then(
			(info) => info as Info,
			() => undefined,
		);
	/** The module's info once it is done, or the last one asked by `until`. */
	const doneBy = async (id: string, until: number) => {
		let info = await infoOf(id);
		while (!finished(info?.status) && now() < until && !signal?.aborted) {
			await sleep(timing.pollMs);
			info = (await infoOf(id)) ?? info;
		}
		return info;
	};
	const runs: ModuleRun[] = [];
	for (const test of plan.tests) {
		if (signal?.aborted) break;
		const runner = await suite
			.call("POST", `api/runner?test=${test}&plan=${plan.id}&variant=${variant}`)
			.catch((failed: unknown) => ({ status: 0, body: String(failed) }));
		const id = (runner.body as { id?: unknown } | undefined)?.id;
		if (typeof id !== "string") {
			await record(test, runner, []);
			runs.push({
				test,
				variant: plan.variant,
				status: `not started (${runner.status})`,
				result: undefined,
				log: [],
			});
			continue;
		}
		let info = await doneBy(id, now() + timing.moduleMs);
		let status = String(info?.status);
		if (!finished(info?.status) && signal?.aborted) {
			// The suite's calls end with the signal: the suite's own stop takes this module down.
			await record(test, info, []);
			runs.push({
				test,
				variant: plan.variant,
				status: `aborted (${status})`,
				result: info?.result,
				log: [],
			});
			break;
		}
		if (!finished(info?.status)) {
			const stopped = await suite.call("DELETE", `api/runner/${id}`).catch(() => ({ status: 0 }));
			info = (await doneBy(id, now() + timing.stopMs)) ?? info;
			status = `timed out (${status}; stopped ${stopped.status}, then ${String(info?.status)})`;
		}
		if (info?.status === "INTERRUPTED") await sleep(timing.settleMs);
		const log = await suite.api(`api/log/${id}`).catch(() => undefined);
		await record(test, info, log ?? []);
		runs.push({
			test,
			variant: plan.variant,
			status: Array.isArray(log) ? status : `${status}, its log unread`,
			result: info?.result,
			log: Array.isArray(log) ? log : [],
		});
	}
	return runs;
}
