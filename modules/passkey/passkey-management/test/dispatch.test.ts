import { expect, it } from "vitest";
import { dispatchOver } from "../src/dispatch/dispatch.ts";

function dispatch(max = 2) {
	const told = { dropped: 0, failed: [] as unknown[] };
	const d = dispatchOver({
		max,
		told: { dropped: () => told.dropped++, failed: (e) => told.failed.push(e) },
	});
	return { d, told };
}
/** A job held until the test lets it end. */
function held() {
	let end = () => {};
	const done = new Promise<void>((resolve) => {
		end = resolve;
	});
	let ran = false;
	return {
		job: async () => {
			ran = true;
			await done;
		},
		end: () => end(),
		ran: () => ran,
	};
}

it("runs no job before start, and none after stop", async () => {
	const { d, told } = dispatch();
	const before = held();
	d.put(before.job);
	d.start();
	await d.stop(new AbortController().signal);
	const after = held();
	d.put(after.job);
	await Promise.resolve();
	expect([before.ran(), after.ran(), told.dropped]).toEqual([false, false, 2]);
});

it("runs each job apart from the put, and drops one past the bound, never waiting", async () => {
	const { d, told } = dispatch(2);
	d.start();
	const [a, b, c] = [held(), held(), held()];
	d.put(a.job);
	d.put(b.job);
	d.put(c.job);
	expect(a.ran()).toBe(false);
	await Promise.resolve();
	await Promise.resolve();
	expect([a.ran(), b.ran(), c.ran(), told.dropped]).toEqual([true, true, false, 1]);
	a.end();
	b.end();
	await d.stop(new AbortController().signal);
});

it("tells of a job that throws, at once or later", async () => {
	const { d, told } = dispatch();
	d.start();
	d.put((() => {
		throw new Error("at once");
	}) as never);
	d.put(async () => {
		throw new Error("later");
	});
	await d.stop(new AbortController().signal);
	expect(told.failed.map((e) => (e as Error).message).sort()).toEqual(["at once", "later"]);
});

it("waits at stop for the jobs under way, until the signal aborts", async () => {
	const { d } = dispatch();
	d.start();
	const slow = held();
	d.put(slow.job);
	const deadline = new AbortController();
	let stopped = false;
	const stopping = d.stop(deadline.signal).then(() => {
		stopped = true;
	});
	await Promise.resolve();
	expect(stopped).toBe(false);
	deadline.abort();
	await stopping;
	expect(stopped).toBe(true);
	slow.end();
});
