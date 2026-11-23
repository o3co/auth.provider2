import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { testServer } from "@mod/http-server/testing";
import { metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { afterEach, beforeEach, expect, it } from "vitest";
import { discovery } from "../src/contract.ts";
import discoveryModule from "../src/module.ts";

const runtime = quietRuntime();
const openid = ".well-known/openid-configuration";
const oauth = ".well-known/oauth-authorization-server";

let dir = "";
beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "discovery-publish-"));
});
afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

const item = (name: string, value: unknown) =>
	defineModule({ name: `item-${name}`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(metadata).by(() => ({ name, value })),
	]);

/** discovery beside http and issuer, the endpoints on the Front's origin, with these modules besides. */
const composition = (extra: Module[], url = "https://as.example") => ({
	modules: [http, testServer(), issuerModule, discoveryModule, ...extra],
	config: {
		...kernelConfig(),
		...httpConfig({ "public-origin": "https://front.example" }),
		...issuerConfig({ url }),
	},
	runtime,
});

const published = async (extra: Module[], url?: string) =>
	(await assemble(composition(extra, url))).get(discovery);

/** Every file under the directory, by its path there. */
const files = async () =>
	(await readdir(dir, { recursive: true, withFileTypes: true }))
		.filter((entry) => entry.isFile())
		.map((entry) => join(entry.parentPath, entry.name).slice(dir.length + 1))
		.sort();

const read = async (path: string) => {
	const text = await readFile(join(dir, path), "utf8");
	return { text, json: JSON.parse(text) as Record<string, unknown> };
};

it("writes one document at both well-known names, the configured issuer first and each contributed member [oidc-discovery-3-a] [oidc-discovery-4-a] [oidc-discovery-4.1-a] [oidc-discovery-4.3-a] [rfc8414-2-a] [rfc8414-3.1-a] [rfc8414-3.3-a] [oidc-discovery-4-c] [oidc-discovery-4.2-a] [rfc8414-3.2-a] [rfc9207-2.3-a]", async () => {
	const d = await published([
		item("b_supported", ["x"]),
		item("a_endpoint", "https://front.example/a"),
		item("gone", undefined),
		item("left", undefined),
	]);
	expect(await d.publish([dir])).toEqual({
		lines: [`wrote ${join(dir, openid)}`, `wrote ${join(dir, oauth)}`],
		code: 0,
	});
	for (const path of [openid, oauth]) {
		const { json } = await read(path);
		expect(json).toEqual({
			issuer: "https://as.example",
			b_supported: ["x"],
			a_endpoint: "https://front.example/a",
		});
		expect(Object.keys(json)[0]).toBe("issuer");
	}
});

it("writes the document under the registered well-known names alone [rfc8414-3-c]", async () => {
	await (await published([])).publish([dir]);
	expect(await files()).toEqual([oauth, openid].sort());
});

it("writes for an issuer with a path where RFC 8414 inserts the well-known name and where OpenID appends it, and not at the root [oidc-discovery-4-a] [oidc-discovery-4.3-a] [rfc8414-3-a] [rfc8414-3.1-a] [rfc8414-3.3-a]", async () => {
	await (await published([], "https://as.example/tenant/a")).publish([dir]);
	// A document at the root names the issuer without the path, which a client must refuse.
	expect(await files()).toEqual(
		[`${oauth}/tenant/a`, `tenant/a/${openid}`].sort().map((p) => join(p)),
	);
	for (const path of [`${oauth}/tenant/a`, `tenant/a/${openid}`]) {
		expect((await read(path)).json).toEqual({ issuer: "https://as.example/tenant/a" });
	}
});

it("writes a path as the issuer URL writes it, never one leaving the directory", async () => {
	await (await published([], "https://as.example/a%2F..%2F..%2Fb")).publish([dir]);
	expect(await files()).toEqual([`${oauth}/a%2F..%2F..%2Fb`, `a%2F..%2F..%2Fb/${openid}`].sort());
});

it("leaves out a member whose value is absent or a list with no elements, whichever module gives it [oidc-discovery-4.2-b] [rfc8414-3.2-b]", async () => {
	await (
		await published([
			item("absent", undefined),
			item("none_supported", []),
			item("one_supported", ["x"]),
			item("flag", false),
			item("empty_text", ""),
		])
	).publish([dir]);
	for (const path of [openid, oauth]) {
		expect((await read(path)).json, path).toEqual({
			issuer: "https://as.example",
			one_supported: ["x"],
			flag: false,
			empty_text: "",
		});
	}
});

it("writes the document fixed at boot, the same bytes each run, as one JSON object and a newline", async () => {
	const d = await published([item("a_endpoint", "https://front.example/a")]);
	await d.publish([dir]);
	const first = (await read(openid)).text;
	await d.publish([dir]);
	expect((await read(openid)).text).toBe(first);
	expect(first).toBe(
		`${JSON.stringify({ issuer: "https://as.example", a_endpoint: "https://front.example/a" })}\n`,
	);
});

it("answers a usage line and 64 where it is not given one directory, writing nothing", async () => {
	const d = await published([]);
	for (const args of [[], [dir, dir]]) {
		expect(await d.publish(args)).toEqual({
			lines: ["usage: discovery-publish <directory>"],
			code: 64,
		});
	}
	expect(await files()).toEqual([]);
});

it("refuses boot when two modules contribute one member", async () => {
	const refused = await published([
		item("same", 1),
		defineModule({ name: "again", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(metadata).by(() => ({ name: "same", value: 2 })),
		]),
	]).then(
		() => false,
		(error) => error instanceof BootRefused,
	);
	expect(refused).toBe(true);
});

it("takes all it names, with items and with none", async () => {
	for (const extra of [[], [item("a_endpoint", "https://front.example/a")]]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(composition(extra))).discovery).toBeUndefined();
	}
});
