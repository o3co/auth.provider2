import { readFileSync } from "node:fs";
import { BootRefused } from "@mod/kernel";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { describe, expect, it } from "vitest";
import { boot } from "./fixtures/world.ts";

describe("transparency-local's module", () => {
	it("appends as a writer of its own instance, of the Core generation keys signs as", async () => {
		const one = await boot();
		const two = await boot();
		expect(one.log.writer.generation).toBe(one.keys.generation());
		expect(one.log.writer.instance).not.toBe(two.log.writer.instance);
	});

	it("stands breaking core-compromise-contained: the log and its judgment are the Core's own", async () => {
		const { app } = await boot({ modules: [promisesModule] });
		const contained = app
			.get(promises)
			.judgment()
			.find((j) => j.promise === promiseNames.coreContained);
		expect(contained).toMatchObject({
			held: false,
			breaking: [
				{ by: "transparency-local", reason: expect.stringMatching(/^not recommended: .*Core/) },
			],
		});
	});

	it("asks the operator to accept the promise its stance breaks, by the stance's name", () => {
		const manifest = JSON.parse(
			readFileSync(new URL("../package.json", import.meta.url), "utf8"),
		) as { asks: readonly string[] };
		expect(manifest.asks.join("\n")).toMatch(
			new RegExp(`^Not recommended: \`${promiseNames.coreContained}\` does not hold`, "m"),
		);
	});

	it("refuses boot where no origin is set to judge an assertion for", async () => {
		const refused = await boot({ section: { origin: undefined } }).catch((e: unknown) => e);
		expect(BootRefused.is(refused)).toBe(true);
		expect((refused as BootRefused).refusals.map((r) => r.where).join()).toMatch(
			/transparency-local\.origin/,
		);
	});
});
