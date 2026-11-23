import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { counter, gauge, histogram, type Instrument, instruments } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import metricsLog from "../src/module.ts";

let recording = recordingLog();
let stops: (() => Promise<void>)[] = [];
beforeEach(() => {
	recording = recordingLog();
	vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
});
afterEach(async () => {
	for (const stop of stops) await stop();
	stops = [];
	vi.useRealTimers();
});

const emitting = (...made: (() => Instrument)[]) =>
	defineModule({ name: "emitter", replicaSafe: false, takes: [] }, (m) =>
		made.map((make) => m.contribute(instruments).by(make)),
	);

const composition = (modules: Module[], settings?: Record<string, unknown>) => ({
	modules: [metricsModule, metricsLog, ...modules],
	config: { ...kernelConfig(), ...(settings ? { "metrics-log": settings } : {}) },
	runtime: quietRuntime({ log: recording.log }),
});

async function started(modules: Module[], settings?: Record<string, unknown>) {
	const app = await assemble(composition(modules, settings));
	await app.start();
	stops.push(() => app.stop(1000));
	return app;
}

/** The sample lines logged so far. */
const samples = () => recording.lines().filter((line) => line.event === "metrics.sample");

/** The promise's gauge, as a module that judges a promise may make it. */
const held = (value: () => number) =>
	gauge(
		{
			name: "promise_held",
			help: "Whether the promise holds.",
			labels: { name: ["front-compromise-new-authorization"], basis: ["configuration"] },
		},
		() => [
			{
				labels: { name: "front-compromise-new-authorization", basis: "configuration" },
				value: value(),
			},
		],
	);

it("writes what metrics samples as one info line once booted, then every 60 s", async () => {
	const requests = counter({ name: "requests_total", help: "Requests.", labels: {} });
	const work = histogram({
		name: "work_seconds",
		help: "Work.",
		labels: { kind: ["a"] },
		buckets: [0.5, 1],
	});
	let holds = 0;
	await started([
		emitting(
			() => requests,
			() => work,
			() => held(() => holds),
		),
	]);
	// Written as start ends, before any interval, so each boot tells where the promises stand.
	expect(samples()).toEqual([
		{
			level: "info",
			event: "metrics.sample",
			fields: {
				'promise_held{name="front-compromise-new-authorization",basis="configuration"}': 0,
			},
		},
	]);
	requests.add({}, 3);
	work.observe({ kind: "a" }, 0.75);
	await vi.advanceTimersByTimeAsync(59_999);
	expect(samples()).toHaveLength(1);
	await vi.advanceTimersByTimeAsync(1);
	expect(samples().slice(1)).toEqual([
		{
			level: "info",
			event: "metrics.sample",
			fields: {
				"requests_total{}": 3,
				'work_seconds{kind="a"}.le=0.5': 0,
				'work_seconds{kind="a"}.le=1': 1,
				'work_seconds{kind="a"}.sum': 0.75,
				'work_seconds{kind="a"}.count': 1,
				'promise_held{name="front-compromise-new-authorization",basis="configuration"}': 0,
			},
		},
	]);
	// Each gauge is read anew at each sample.
	holds = 1;
	await vi.advanceTimersByTimeAsync(60_000);
	expect(samples()).toHaveLength(3);
	expect(
		samples()[2]?.fields[
			'promise_held{name="front-compromise-new-authorization",basis="configuration"}'
		],
	).toBe(1);
});

it("writes a label value as JSON writes a string, so no value is read as another label or series", async () => {
	const odd = counter({
		name: "odd_total",
		help: "Odd.",
		labels: { a: ['x",b="y}'], b: ["z"] },
	});
	await started([emitting(() => odd)]);
	odd.add({ a: 'x",b="y}', b: "z" });
	await vi.advanceTimersByTimeAsync(60_000);
	expect(samples()[1]?.fields).toEqual({ 'odd_total{a="x\\",b=\\"y}",b="z"}': 1 });
});

it("leaves out a gauge whose read fails, and still writes the line", async () => {
	await started([
		emitting(
			() =>
				gauge({ name: "broken", help: "Broken.", labels: {} }, () => {
					throw new Error("down");
				}),
			() => held(() => 1),
		),
	]);
	expect(samples()[0]?.fields).toEqual({
		'promise_held{name="front-compromise-new-authorization",basis="configuration"}': 1,
	});
});

it("writes a line with no series where nothing was counted", async () => {
	await started([emitting(() => counter({ name: "idle_total", help: "Idle.", labels: {} }))]);
	await vi.advanceTimersByTimeAsync(60_000);
	expect(samples()).toEqual(Array(2).fill({ level: "info", event: "metrics.sample", fields: {} }));
});

it("samples at the interval its section sets, from 1 s to 1 h", async () => {
	await started([emitting(() => held(() => 1))], { interval: "5s" });
	await vi.advanceTimersByTimeAsync(4_999);
	expect(samples()).toHaveLength(1);
	await vi.advanceTimersByTimeAsync(1);
	expect(samples()).toHaveLength(2);
	for (const interval of ["999ms", "2h", "never"]) {
		const refused = await assemble(composition([], { interval })).catch((e: unknown) => e);
		expect(refused, interval).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["metrics-log.interval"]);
	}
});

it("writes nothing before start or once stopped, and nothing in an assembly never started", async () => {
	const app = await assemble(composition([emitting(() => held(() => 1))]));
	await vi.advanceTimersByTimeAsync(60_000);
	expect(samples()).toEqual([]);
	await app.start();
	await app.stop(1000);
	await vi.advanceTimersByTimeAsync(120_000);
	expect(samples()).toHaveLength(1);
	recording = recordingLog();
	const tool = await assemble({
		...composition([emitting(() => held(() => 1))]),
		neverStarted: true,
	});
	await expect(tool.start()).rejects.toThrow(TypeError);
	await tool.stop(1000);
	expect(samples()).toEqual([]);
});

it("refuses boot without metrics, and takes all it names", async () => {
	const refused = await assemble({
		modules: [metricsLog],
		config: kernelConfig(),
		runtime: quietRuntime(),
	}).catch((e: unknown) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((await takesUnused(composition([])))["metrics-log"]).toBeUndefined();
});
