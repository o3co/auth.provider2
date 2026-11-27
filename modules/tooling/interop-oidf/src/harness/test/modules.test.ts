import { describe, expect, it } from "vitest";
import { runModules, type Timing } from "./modules.ts";

const variant = { openid: "openid_connect" };

/** A suite whose modules each answer infos in turn, the last kept; every call recorded. */
function fakeSuite(
	infos: Readonly<Record<string, readonly (object | "fail")[]>>,
	ids: Readonly<Record<string, string>> = {},
) {
	const calls: string[] = [];
	const asked = new Map<string, number>();
	const suite = {
		async call(method: "GET" | "POST" | "DELETE", path: string) {
			calls.push(`${method} ${path}`);
			if (method === "POST") {
				const test = /test=([^&]+)/.exec(path)?.[1] ?? "";
				return ids[test] === "none"
					? { status: 500, body: {} }
					: { status: 201, body: { id: ids[test] ?? `id-${test}` } };
			}
			return { status: 200, body: {} };
		},
		async api(path: string) {
			calls.push(`GET ${path}`);
			const id = path.split("/").pop() ?? "";
			if (path.startsWith("api/log/")) return [{ src: "log", id }];
			const list = infos[id.replace(/^id-/, "")] ?? [];
			const i = asked.get(id) ?? 0;
			asked.set(id, i + 1);
			const answer = list[Math.min(i, list.length - 1)];
			if (answer === "fail") throw new Error("the suite did not answer");
			return answer;
		},
	};
	return { suite, calls };
}

/** A clock the sleeps move, so a test of minutes takes none. */
function clocked(over: Partial<Timing> = {}): Timing {
	let t = 0;
	return {
		moduleMs: 10_000,
		pollMs: 1000,
		stopMs: 3000,
		settleMs: 500,
		now: () => t,
		sleep: async (ms) => {
			t += ms;
		},
		...over,
	};
}

describe("a plan's modules, each in turn", () => {
	it("keeps each module's info and log under the plan's variant, asking again past a failed ask", async () => {
		const { suite } = fakeSuite({
			a: [
				{ status: "RUNNING" },
				"fail",
				{ status: "FINISHED", result: "PASSED", variant: { other: "x" } },
			],
			b: [{ status: "INTERRUPTED", result: "FAILED" }],
		});
		const recorded: string[] = [];
		const runs = await runModules(
			suite,
			{ id: "p", variant, tests: ["a", "b"] },
			clocked(),
			async (test) => {
				recorded.push(test);
			},
		);
		expect(runs).toEqual([
			{
				test: "a",
				variant,
				status: "FINISHED",
				result: "PASSED",
				log: [{ src: "log", id: "id-a" }],
			},
			{
				test: "b",
				variant,
				status: "INTERRUPTED",
				result: "FAILED",
				log: [{ src: "log", id: "id-b" }],
			},
		]);
		expect(recorded).toEqual(["a", "b"]);
	});

	it("stops a module past its time by DELETE, awaits its stop before its log or the next module, and keeps it timed out", async () => {
		const { suite, calls } = fakeSuite({
			slow: [{ status: "WAITING" }],
			next: [{ status: "FINISHED" }],
		});
		const runs = await runModules(
			suite,
			{ id: "p", variant, tests: ["slow", "next"] },
			clocked(),
			async () => {},
		);
		expect(calls.filter((c) => c.startsWith("POST"))).toHaveLength(2);
		expect(runs[0]?.status).toBe("timed out (WAITING; stopped 200, then WAITING)");
		// Still waiting two asks after the DELETE, then ended: the log and the next module come after.
		const waiting = Array(13).fill({ status: "WAITING" });
		const stopping = fakeSuite({
			slow: [...waiting, { status: "INTERRUPTED" }],
			next: [{ status: "FINISHED" }],
		});
		const ended = await runModules(
			stopping.suite,
			{ id: "p", variant, tests: ["slow", "next"] },
			clocked(),
			async () => {},
		);
		expect(ended[0]?.status).toBe("timed out (WAITING; stopped 200, then INTERRUPTED)");
		const order = (call: string) => stopping.calls.indexOf(call);
		const asked = stopping.calls.filter((c) => c === "GET api/info/id-slow");
		expect(asked).toHaveLength(14);
		expect(stopping.calls.lastIndexOf("GET api/info/id-slow")).toBeGreaterThan(
			order("DELETE api/runner/id-slow") + 2,
		);
		expect(order("GET api/log/id-slow")).toBeGreaterThan(
			stopping.calls.lastIndexOf("GET api/info/id-slow"),
		);
		expect(
			stopping.calls.findIndex((c) => c.startsWith("POST") && c.includes("test=next")),
		).toBeGreaterThan(order("GET api/log/id-slow"));
	});

	it("ends a module's wait at once when the signal ends, keeping it aborted with no DELETE, and starts no other", async () => {
		const abort = new AbortController();
		const { suite, calls } = fakeSuite({
			slow: [{ status: "WAITING" }],
			next: [{ status: "FINISHED" }],
		});
		const timing = clocked();
		const runs = await runModules(
			suite,
			{ id: "p", variant, tests: ["slow", "next"] },
			{
				...timing,
				sleep: async (ms) => {
					await timing.sleep?.(ms);
					if ((timing.now?.() ?? 0) >= 3000) abort.abort();
				},
			},
			async () => {},
			abort.signal,
		);
		expect(runs).toEqual([
			{ test: "slow", variant, status: "aborted (WAITING)", result: undefined, log: [] },
		]);
		expect(calls.some((c) => c.startsWith("DELETE"))).toBe(false);
		expect(calls.filter((c) => c === "GET api/info/id-slow")).toHaveLength(4);
	});

	it("keeps a module the suite would not start as not started, and starts none past an abort", async () => {
		const { suite, calls } = fakeSuite({ b: [{ status: "FINISHED" }] }, { a: "none" });
		const runs = await runModules(
			suite,
			{ id: "p", variant, tests: ["a", "b"] },
			clocked(),
			async () => {},
		);
		expect(runs.map((r) => r.status)).toEqual(["not started (500)", "FINISHED"]);
		const aborted = AbortSignal.abort();
		const none = await runModules(
			suite,
			{ id: "p", variant, tests: ["b"] },
			clocked(),
			async () => {},
			aborted,
		);
		expect(none).toEqual([]);
		expect(calls.filter((c) => c.startsWith("POST"))).toHaveLength(2);
	});
});
