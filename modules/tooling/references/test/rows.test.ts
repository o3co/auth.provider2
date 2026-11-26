import { parseString } from "@o3co/ts.hocon";
import { expect, it } from "vitest";
import { describedOf, type JsonSchema, referenceConfOf, rowsOf } from "../src/contract.ts";

it("writes a section's defaults as HOCON: each described, a unit value bare, a key without a default or within an optional object as a comment", () => {
	const rows = [
		{ key: "s.ttl", type: "integer", default: "5m", required: false, description: "How long." },
		{ key: "s.retry.hosts", type: "list of string", default: ["a"], required: false },
		{ key: "s.url", type: "string", required: true },
		{ key: "s.proxy", type: "string", required: false },
		{ key: "s.next.alg", type: "string", default: "a", required: false, within: "s.next" },
		{ key: "s.next.id", type: "string", required: true, within: "s.next" },
		{
			key: "s.anchors",
			type: "list of string",
			required: true,
			when: [{ key: "s.mode", values: ["pki", "chain"] }],
		},
	];
	const conf = referenceConfOf({ section: "s", owner: "@mod/s", rows });
	expect(conf.split("\n").slice(2)).toEqual([
		"s {",
		"\t# How long.",
		"\tttl = 5m",
		'\tretry.hosts = ["a"]',
		"\t# url: required",
		"\t# proxy: optional",
		'\t# next.alg = "a" (when next is set)',
		"\t# next.id: required when next is set",
		"\t# anchors: required when mode is pki or chain",
		"}",
		"",
	]);
	expect(parseString(conf).get("s")).toEqual({ ttl: "5m", retry: { hosts: ["a"] } });
});

it("requires a key inside an optional object only once the object is set, and holds its default only then", () => {
	const key = {
		type: "object",
		required: ["id"],
		properties: { id: { type: "string" }, alg: { type: "string", default: "a" } },
	};
	const schema = {
		type: "object",
		required: ["current"],
		properties: { current: key, next: key, kept: { ...key, default: {} } },
	};
	const rows = rowsOf(schema, ["k"]);
	expect(rows).toEqual([
		{ key: "k.current.id", type: "string", required: true },
		{ key: "k.current.alg", type: "string", default: "a", required: false },
		{ key: "k.next.id", type: "string", required: true, within: "k.next" },
		{ key: "k.next.alg", type: "string", default: "a", required: false, within: "k.next" },
		{ key: "k.kept.id", type: "string", required: false },
		{ key: "k.kept.alg", type: "string", default: "a", required: false },
	]);
});

it("shows a nested object's own description before its first key, in the HOCON, nested ones too", () => {
	const schema = {
		type: "object",
		properties: {
			caps: {
				type: "object",
				description: "What every cap holds to.",
				default: {},
				properties: {
					size: { type: "integer", default: 1 },
					inner: {
						type: "object",
						description: "Deeper.",
						default: {},
						properties: { depth: { type: "integer", default: 2 } },
					},
				},
			},
			plain: { type: "object", properties: { n: { type: "integer", default: 3 } } },
		},
	};
	const objects = describedOf(schema, ["k"]);
	expect(objects).toEqual([
		{ key: "k.caps", description: "What every cap holds to." },
		{ key: "k.caps.inner", description: "Deeper." },
	]);
	const rows = rowsOf(schema, ["k"]);
	const section = { section: "k", owner: "@mod/k", rows, objects };
	const conf = referenceConfOf(section).split("\n");
	expect(conf.indexOf("\t# caps: What every cap holds to.")).toBe(
		conf.indexOf("\tcaps.size = 1") - 1,
	);
	expect(conf.indexOf("\t# caps.inner: Deeper.")).toBe(conf.indexOf("\tcaps.inner.depth = 2") - 1);
});

it("holds a key nested in an optional object to the nearest optional object, a list of objects kept as one row", () => {
	const object = (properties: Record<string, JsonSchema>, required: string[] = []): JsonSchema => ({
		type: "object",
		required,
		properties,
	});
	const next = object(
		{
			pair: object({ x: { type: "string" } }, ["x"]),
			extra: object({ y: { type: "string" } }, ["y"]),
			tuned: { ...object({ z: { type: "string" } }, ["z"]), default: {} },
			hosts: { type: "array", items: object({ name: { type: "string" } }, ["name"]) },
		},
		["pair"],
	);
	expect(rowsOf(object({ next }), ["k"])).toEqual([
		{ key: "k.next.pair.x", type: "string", required: true, within: "k.next" },
		{ key: "k.next.extra.y", type: "string", required: true, within: "k.next.extra" },
		{ key: "k.next.tuned.z", type: "string", required: false, within: "k.next" },
		{ key: "k.next.hosts", type: "list of map", required: false, within: "k.next" },
	]);
});

it("writes a union told apart by one key by its variants: a key's default and requiredness when that key takes theirs", () => {
	const schema: JsonSchema = {
		oneOf: [
			{
				type: "object",
				required: ["mode"],
				properties: { mode: { const: "off", description: "Whether it runs." } },
			},
			{
				type: "object",
				required: ["mode", "hosts"],
				properties: {
					mode: { enum: ["on", "loud"] },
					hosts: { type: "array", items: { type: "string" } },
					header: { type: "string", default: "a" },
				},
			},
			{
				type: "object",
				required: ["mode", "header"],
				properties: { mode: { const: "quiet" }, header: { type: "string" } },
			},
		],
	};
	const rows = rowsOf(schema, ["u"]);
	const by = (values: string[]) => [{ key: "u.mode", values }];
	expect(rows).toEqual([
		{
			key: "u.mode",
			type: "off | on | loud | quiet",
			required: true,
			description: "Whether it runs.",
		},
		{ key: "u.hosts", type: "list of string", required: true, when: by(["on", "loud"]) },
		{ key: "u.header", type: "string", default: "a", required: false, when: by(["on", "loud"]) },
		{ key: "u.header", type: "string", required: true, when: by(["quiet"]) },
	]);
});

it("holds a variant's object's keys to both variants, outermost first, beside an optional object's", () => {
	const inner: JsonSchema = {
		oneOf: [
			{ type: "object", required: ["mode"], properties: { mode: { const: "off" } } },
			{
				type: "object",
				required: ["mode", "hosts"],
				properties: { mode: { enum: ["a", "b", "c"] }, hosts: { type: "string" } },
			},
		],
	};
	const schema: JsonSchema = {
		oneOf: [
			{ type: "object", required: ["kind"], properties: { kind: { const: "plain" } } },
			{
				type: "object",
				required: ["kind", "check"],
				properties: { kind: { const: "checked" }, check: inner, extra: inner },
			},
		],
	};
	const rows = rowsOf(schema, ["s"]).filter((r) => r.key.endsWith(".hosts"));
	expect(rows.map((r) => [r.key, r.required, r.within, r.when])).toEqual([
		[
			"s.check.hosts",
			true,
			undefined,
			[
				{ key: "s.kind", values: ["checked"] },
				{ key: "s.check.mode", values: ["a", "b", "c"] },
			],
		],
		[
			"s.extra.hosts",
			true,
			"s.extra",
			[
				{ key: "s.kind", values: ["checked"] },
				{ key: "s.extra.mode", values: ["a", "b", "c"] },
			],
		],
	]);
});

it("merges the keys of a union no one key tells apart, required only where every variant requires them", () => {
	const schema: JsonSchema = {
		oneOf: [
			{ type: "object", required: ["a"], properties: { a: { type: "string" } } },
			{
				type: "object",
				required: ["a", "b"],
				properties: { a: { type: "string" }, b: { type: "string" } },
			},
		],
	};
	expect(rowsOf(schema, ["u"])).toEqual([
		{ key: "u.a", type: "string", required: true },
		{ key: "u.b", type: "string", required: false },
	]);
});
