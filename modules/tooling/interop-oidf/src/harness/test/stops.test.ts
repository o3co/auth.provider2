import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { stoppedWhenEnded } from "./stops.ts";

const unhandled: unknown[] = [];
const keep = (reason: unknown) => unhandled.push(reason);
beforeEach(() => {
	unhandled.length = 0;
	process.on("unhandledRejection", keep);
});
afterEach(async () => {
	await new Promise((r) => setTimeout(r, 20));
	process.off("unhandledRejection", keep);
	expect(unhandled).toEqual([]);
});

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

describe("a run's parts, stopped however it ends", () => {
	it("stops every part held, the last first, once the body ends, and answers its value", async () => {
		const stopped: string[] = [];
		const { ran, problems } = await stoppedWhenEnded(new AbortController().signal, async (held) => {
			held(async () => stopped.push("a"));
			held(async () => stopped.push("b"));
			return 7;
		});
		expect(ran).toEqual({ value: 7 });
		expect(stopped).toEqual(["b", "a"]);
		expect(problems).toEqual([]);
	});

	it("tells each stop's failure, the body's own failure kept apart, every stop tried", async () => {
		const stopped: string[] = [];
		const { ran, problems } = await stoppedWhenEnded(new AbortController().signal, async (held) => {
			held(async () => stopped.push("a"));
			held(async () => Promise.reject(new Error("b would not stop")));
			throw new Error("the body failed");
		});
		expect(ran).toMatchObject({ failed: expect.objectContaining({ message: "the body failed" }) });
		expect(stopped).toEqual(["a"]);
		expect(problems).toEqual([expect.objectContaining({ message: "b would not stop" })]);
	});

	it("stops what it holds once the signal ends, then stops a part the body starts after and goes no further, its stop awaited and told", async () => {
		const abort = new AbortController();
		const steps: string[] = [];
		let starting: (() => void) | undefined;
		const result = stoppedWhenEnded(abort.signal, async (held) => {
			held(async () => steps.push("early stopped"));
			await new Promise<void>((r) => {
				starting = r;
			});
			steps.push("late started");
			held(async () => {
				await tick();
				steps.push("late stopped");
				throw new Error("late would not stop");
			});
			steps.push("next started");
			return "never";
		});
		await tick();
		abort.abort("the deadline");
		await tick();
		expect(steps).toEqual(["early stopped"]);
		starting?.();
		const { ran, after, problems } = await result;
		expect(ran).toMatchObject({
			failed: expect.objectContaining({ message: "ended: the deadline" }),
		});
		expect(after).toBeUndefined();
		expect(steps).toEqual(["early stopped", "late started", "late stopped"]);
		expect(problems).toEqual([expect.objectContaining({ message: "late would not stop" })]);
	});

	it("awaits a body ended by its signal, answering what it failed or answered of its own apart from the stops' failures", async () => {
		const failing = new AbortController();
		const own = stoppedWhenEnded(failing.signal, async () => {
			await tick(20);
			throw new Error("the suite did not stop");
		});
		failing.abort("cancel");
		const told = await own;
		expect(told.ran).toMatchObject({
			failed: expect.objectContaining({ message: "ended: cancel" }),
		});
		expect(told.after).toMatchObject({
			failed: expect.objectContaining({ message: "the suite did not stop" }),
		});
		expect(told.problems).toEqual([]);
		const answering = new AbortController();
		const answered = stoppedWhenEnded(answering.signal, async () => {
			await tick(20);
			return "the report";
		});
		answering.abort("cancel");
		expect((await answered).after).toEqual({ value: "the report" });
	});

	it("tells a body that does not end in its time after the signal, and runs none on a signal ended already", async () => {
		const abort = new AbortController();
		const hung = stoppedWhenEnded(abort.signal, () => new Promise<never>(() => {}), 30);
		abort.abort("cancel");
		expect((await hung).problems).toEqual([
			expect.objectContaining({ message: "the run's body did not end within 30 ms of its signal" }),
		]);
		let ran = false;
		const none = await stoppedWhenEnded(AbortSignal.abort("before"), async () => {
			ran = true;
		});
		expect(ran).toBe(false);
		expect(none.ran).toMatchObject({
			failed: expect.objectContaining({ message: "ended: before" }),
		});
	});
});
