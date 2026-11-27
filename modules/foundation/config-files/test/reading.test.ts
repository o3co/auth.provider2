import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BootRefused } from "@mod/kernel";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, loadConfigReading } from "../src/contract.ts";

let dir: string;
let outside: string;
beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "config-reading-"));
	outside = await mkdtemp(join(tmpdir(), "config-outside-"));
});
afterAll(async () => {
	await rm(dir, { recursive: true, force: true });
	await rm(outside, { recursive: true, force: true });
});

describe("a configuration's read set", () => {
	it("answers the tree and every file it read, an include outside the app's among them, and every path looked for and missing", async () => {
		await writeFile(join(outside, "far.conf"), "far = 1\n");
		await writeFile(join(dir, "nested.conf"), "nested = 2\n");
		await writeFile(
			join(dir, "app.conf"),
			`include "nested"\ninclude file("${join(outside, "far.conf")}")\ninclude "absent"\nown = 3\n`,
		);
		const loaded = await loadConfigReading({ files: [join(dir, "app.conf")], env: {} });
		expect(loaded).toMatchObject({ kind: "loaded", tree: { far: 1, nested: 2, own: 3 } });
		if (loaded.kind !== "loaded") throw new Error("refused");
		expect(loaded.reads.read).toEqual(
			expect.arrayContaining([
				join(dir, "app.conf"),
				join(dir, "nested.conf"),
				join(outside, "far.conf"),
			]),
		);
		// A bare include tries its forms: those missing are probed, never read.
		expect(loaded.reads.probed).toEqual(
			expect.arrayContaining([join(dir, "absent.conf"), join(dir, "nested.properties")]),
		);
		expect(loaded.reads.probed).not.toContain(join(dir, "nested.conf"));
		// loadConfig answers the same tree.
		expect(await loadConfig({ files: [join(dir, "app.conf")], env: {} })).toEqual(loaded.tree);
	});

	it("refuses include package(...), in loadConfig too: its lookups are the library's own", async () => {
		await writeFile(join(dir, "pkg.conf"), 'include package("@mod/kernel", "x.conf")\n');
		const source = { files: [join(dir, "pkg.conf")], env: {} };
		const reading = await loadConfigReading(source);
		expect(reading).toMatchObject({ kind: "refused" });
		// Said as it is, so a 0.18 app using one is told what to write instead.
		const told = {
			where: join(dir, "pkg.conf"),
			reason: "include package(...) is not taken: include the file by its path",
		};
		if (reading.kind === "refused") expect(reading.refusal.refusals).toEqual([told]);
		await expect(loadConfig(source)).rejects.toSatisfy(
			(error: unknown) =>
				BootRefused.is(error) && JSON.stringify(error.refusals) === JSON.stringify([told]),
		);
	});

	it("answers a refusal with what was read up to it", async () => {
		await writeFile(join(dir, "good.conf"), "good = 1\n");
		await writeFile(join(dir, "bad.conf"), "bad = {\n");
		const reading = await loadConfigReading({
			files: [join(dir, "good.conf"), join(dir, "bad.conf")],
			env: {},
		});
		expect(reading).toMatchObject({ kind: "refused" });
		if (reading.kind !== "refused") throw new Error("loaded");
		expect(reading.refusal.refusals[0]?.where).toMatch(/bad\.conf/);
		expect(reading.reads.read).toEqual([join(dir, "good.conf"), join(dir, "bad.conf")]);
	});
});
