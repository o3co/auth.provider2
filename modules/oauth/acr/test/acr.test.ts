import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { afterEach, expect, it } from "vitest";
import { acr, amrSources } from "../src/contract.ts";
import acrModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { acrConfig } from "../src/testing.ts";

const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

const proving = (amr: string[], name = "proving", module = name) =>
	defineModule({ name: module, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(amrSources).by(() => ({ name, amr })),
	]);
const published = contract<readonly MetadataItem[]>("published");
const reader = defineModule({ name: "reader", replicaSafe: true, takes: [metadata] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
]);

/** The assembly the tests serve: http, issuer and acr, with this table and these modules. */
const assembly = (values: Record<string, string[][]>, extra: Module[]) => ({
	modules: [http, testServer(), issuerModule, reader, acrModule, ...extra],
	config: {
		...kernelConfig(),
		...httpConfig({ "public-origin": "https://as.example" }),
		...issuerConfig({ url: "https://as.example" }),
		...acrConfig(values),
	},
	runtime,
});

async function serve(values: Record<string, string[][]>, extra: Module[]) {
	const app = await assemble(assembly(values, extra));
	await app.start();
	stop = () => app.stop(1000);
	const listed = async () =>
		app.get(published).find((item) => item.name === "acr_values_supported")?.value;
	return { decided: app.get(acr), listed };
}

const table = {
	"urn:t:zz": [["pwd"]],
	"urn:t:aa": [["hwk"], ["pwd", "otp"]],
};
const proved = () => [proving(["pwd", "otp", "hwk"])];

it("knows the asked acr the table holds, in the order asked, by exact name", async () => {
	const { decided } = await serve(table, proved());
	expect(decided.known("urn:t:none urn:t:aa urn:t:zz")).toEqual(["urn:t:aa", "urn:t:zz"]);
	expect(decided.known("URN:T:AA constructor toString __proto__")).toEqual([]);
});

it("knows an acr only by its own code points, compared one by one: none normalized, recomposed or of another case [oidc-core-14-a] [oidc-core-14-b] [oidc-core-14-c]", async () => {
	const { decided } = await serve({ "urn:t:café": [["pwd"]] }, proved());
	expect(decided.known("urn:t:café")).toEqual(["urn:t:café"]);
	// e and U+0301 is the same text to a reader, normalized, but other code points.
	expect(decided.known("urn:t:café urn:t:CAFÉ urn:t:caf")).toEqual([]);
});

it("meets the first known acr whose one set the session holds whole", async () => {
	const { decided } = await serve(table, proved());
	expect(decided.met(["urn:t:aa", "urn:t:zz"], ["pwd"])).toBe("urn:t:zz");
	expect(decided.met(["urn:t:aa", "urn:t:zz"], ["pwd", "otp"])).toBe("urn:t:aa");
	expect(decided.met(["urn:t:aa"], ["otp"])).toBeUndefined();
	expect(decided.met(["constructor"], ["pwd"])).toBeUndefined();
});

it("answers the session's current acr: the first in the table's order its amr meet, none where they meet none", async () => {
	const { decided } = await serve(table, proved());
	expect(decided.current(["pwd"])).toBe("urn:t:zz");
	expect(decided.current(["hwk"])).toBe("urn:t:aa");
	expect(decided.current(["mfa"])).toBeUndefined();
	await stop();
	expect((await serve({}, [])).decided.current(["pwd"])).toBeUndefined();
});

it("lists the operator's acr in written order, and nothing for an empty table", async () => {
	const { listed } = await serve(table, proved());
	expect(await listed()).toEqual(["urn:t:zz", "urn:t:aa"]);
	await stop();
	expect(await (await serve({}, [])).listed()).toBeUndefined();
});

it("puts names that read as integers first, ascending, and warns at start where the table holds one beside another", async () => {
	const warned = async (values: Record<string, string[][]>) => {
		const logged = recordingLog();
		const app = await assemble({
			...assembly(values, [proving(["pwd", "otp"])]),
			runtime: quietRuntime({ log: logged.log }),
		});
		await app.start();
		stop = () => app.stop(1000);
		const order = app.get(published).find((item) => item.name === "acr_values_supported")?.value;
		const lines = logged.lines().filter((l) => l.event === "acr.values_order");
		await stop();
		return { order, current: app.get(acr).current(["pwd", "otp"]), lines };
	};
	// Written "urn:t:x", "2", "1", "0", as a configuration file holds them; an object reads the integers first.
	const mixed = await warned({
		"urn:t:x": [["pwd"]],
		"2": [["pwd", "otp"]],
		"1": [["pwd"]],
		"0": [["pwd"]],
	});
	expect(mixed.order).toEqual(["0", "1", "2", "urn:t:x"]);
	expect(mixed.current).toBe("0");
	expect(mixed.lines).toEqual([
		{ level: "warn", event: "acr.values_order", fields: { names: "0, 1, 2" } },
	]);
	// Names that do not read as integers keep the written order, and warn of nothing.
	const named = await warned({ "loa-2": [["pwd", "otp"]], "loa-1": [["pwd"]], "01": [["pwd"]] });
	expect(named.order).toEqual(["loa-2", "loa-1", "01"]);
	expect(named.current).toBe("loa-2");
	expect(named.lines).toEqual([]);
	// One entry alone has no order to lose.
	expect((await warned({ "1": [["pwd"]] })).lines).toEqual([]);
});

it("refuses to start with an acr no declared way of logging in can meet, at its key, the amr declared together", async () => {
	const refusals = (run: Promise<unknown>) =>
		run.then(
			() => [],
			(error) => (error instanceof BootRefused ? error.refusals : []),
		);
	expect(await refusals(serve({ "urn:t:hard": [["hwk"]] }, [proving(["pwd"])]))).toEqual([
		{ where: "acr.values.urn:t:hard", reason: "no declared way of logging in can meet it" },
	]);
	// With no way of logging in declared, no acr can be met.
	expect(await refusals(serve({ "urn:t:any": [["pwd"]] }, []))).toEqual([
		{ where: "acr.values.urn:t:any", reason: "no declared way of logging in can meet it" },
	]);
	// A set two ways of logging in prove between them is met, as a login may take both.
	const both = [proving(["pwd"], "first"), proving(["otp"], "second")];
	const { decided } = await serve({ "urn:t:two": [["pwd", "otp"]] }, both);
	expect(decided.current(["pwd", "otp"])).toBe("urn:t:two");
});

it("refuses to start with two declarations of amr under one name", async () => {
	const twice = [proving(["pwd"], "same", "one"), proving(["otp"], "same", "other")];
	await expect(serve({}, twice)).rejects.toBeInstanceOf(BootRefused);
});

it("refuses in its section an acr with no set, or with an empty set", () => {
	for (const values of [{ "urn:t:x": [] }, { "urn:t:x": [[]] }]) {
		expect(section.safeParse({ values }).success, JSON.stringify(values)).toBe(false);
	}
});

it("reads an empty table when the operator sets nothing", () => {
	expect(section.parse({})).toEqual({ values: {} });
});

it("takes all it names, with a table and with none, ways of logging in declared or not", async () => {
	for (const [values, extra] of [
		[table, proved()],
		[{}, []],
		[{}, proved()],
	] as const) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect(
			(await takesUnused(assembly(values, [...extra])))["acr"],
			JSON.stringify(values),
		).toBeUndefined();
	}
});
