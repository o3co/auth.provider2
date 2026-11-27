import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { completedOf, composedWith, fullWith, neededWith } from "../src/composed.ts";
import { declaredIn } from "../src/declared.ts";

// Reading a workspace spawns pnpm, slow on a loaded machine.
vi.setConfig({ testTimeout: 30_000 });

/** An axis whose owner is itself a bridge to http, with three adapters joining it: the default, one sorting before it and one after. */
const declared = declaredIn(join(import.meta.dirname, "joining-adapter"));
const metrics = (names: readonly string[]) => names.filter((n) => n.startsWith("@j/metrics-"));
const app = { app: ["@j/app"] };

it("brings, of the adapters joining their owner, the axis's default alone where nothing is named", () => {
	expect(metrics(composedWith(declared, { features: app }))).toEqual(["@j/metrics-prometheus"]);
});

it("brings none where the axis is chosen to another adapter, or to its owner", () => {
	const chosen = composedWith(declared, {
		features: app,
		axes: { "@j/metrics": "@j/metrics-log" },
	});
	expect(metrics(chosen)).toEqual(["@j/metrics-log"]);
	const owner = composedWith(declared, { features: app, axes: { "@j/metrics": "@j/metrics" } });
	expect(metrics(owner)).toEqual([]);
});

it("brings none where the owner itself comes only as a bridge, its axis chosen to another", () => {
	const relayed = composedWith(declared, {
		features: {},
		add: ["@j/relay"],
		axes: { "@j/metrics": "@j/metrics-log" },
	});
	expect(relayed).toContain("@j/metrics");
	expect(metrics(relayed)).toEqual(["@j/metrics-log"]);
});

it("brings the one named, and composes both where one is named and the other added", () => {
	const named = composedWith(declared, {
		features: app,
		axes: { "@j/metrics": "@j/metrics-push" },
	});
	expect(metrics(named)).toEqual(["@j/metrics-push"]);
	const both = composedWith(declared, {
		features: app,
		add: ["@j/metrics-log"],
		axes: { "@j/metrics": "@j/metrics-prometheus" },
	});
	expect(metrics(both).sort()).toEqual(["@j/metrics-log", "@j/metrics-prometheus"]);
});

it("in completed, needed and full, brings the default only where no other adapter of its axis is given, whatever sorts first", () => {
	expect(metrics(completedOf(declared, ["@j/http"]))).toEqual(["@j/metrics-prometheus"]);
	expect(metrics(completedOf(declared, ["@j/http", "@j/metrics"]))).toEqual([
		"@j/metrics-prometheus",
	]);
	expect(metrics(neededWith(declared, ["@j/app", "@j/metrics"]))).toEqual([
		"@j/metrics-prometheus",
	]);
	expect(metrics(completedOf(declared, ["@j/http", "@j/metrics", "@j/metrics-log"]))).toEqual([
		"@j/metrics-log",
	]);
	expect(metrics(neededWith(declared, ["@j/app", "@j/metrics-log"]))).toEqual(["@j/metrics-log"]);
	expect(metrics(fullWith(declared))).toEqual(["@j/metrics-prometheus"]);
	expect(metrics(fullWith(declared, ["@j/metrics-log"]))).toEqual(["@j/metrics-log"]);
});

/** The default joining its owner and a bridge that comes later, and another adapter, sorting first, joining the owner alone. */
const chain = declaredIn(join(import.meta.dirname, "joining-chain"));

it("brings the default, not an adapter whose joins are met first, where the default's come after", () => {
	const adapters = (names: readonly string[]) => names.filter((n) => n === "@k/a" || n === "@k/d");
	expect(adapters(completedOf(chain, ["@k/m"]))).toEqual(["@k/d"]);
	expect(adapters(neededWith(chain, ["@k/m"]))).toEqual(["@k/d"]);
	expect(adapters(fullWith(chain))).toEqual(["@k/d"]);
});

/** The default joining its owner and another axis's adapter, which itself comes only as a bridge, and another adapter, sorting first. */
const cross = declaredIn(join(import.meta.dirname, "joining-cross"));

it("brings the default where what lets it come is itself a joining adapter, whatever sorts first", () => {
	const adapters = (names: readonly string[]) =>
		names.filter((n) => ["@x/a", "@x/e", "@x/z"].includes(n)).sort();
	expect(adapters(completedOf(cross, ["@x/m", "@x/x"]))).toEqual(["@x/e", "@x/z"]);
	expect(adapters(neededWith(cross, ["@x/m", "@x/x"]))).toEqual(["@x/e", "@x/z"]);
});

/** The default joining its owner and a feature only a bridge needs, and another adapter joining the owner alone. */
const needing = declaredIn(join(import.meta.dirname, "joining-need"));

it("brings the default where what lets it come is reached through a bridge's need, in a later round", () => {
	const adapters = (names: readonly string[]) => names.filter((n) => n === "@n/a" || n === "@n/d");
	expect(adapters(neededWith(needing, ["@n/h"]))).toEqual(["@n/d"]);
	expect(adapters(fullWith(needing))).toEqual(["@n/d"]);
});

it("brings no joining adapter but the default where the default joins, though the default cannot come", () => {
	const adapters = (names: readonly string[]) =>
		names.filter((n) => ["@x/a", "@x/e", "@x/z"].includes(n)).sort();
	expect(adapters(completedOf(cross, ["@x/m", "@x/x", "@x/xd"]))).toEqual([]);
});
