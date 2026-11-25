import { wireCertificates } from "@mod/front-relay/testing";
import { assemble } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { promiseNames, promises } from "@mod/promises";
import { afterAll, beforeAll, expect, it } from "vitest";
import { features, pattern } from "./pattern.ts";

let certificates: Awaited<ReturnType<typeof wireCertificates>>;
beforeAll(async () => {
	certificates = await wireCertificates();
});
afterAll(() => certificates.remove());

const spec = (change: readonly string[] = []) => ({
	certificates,
	origin: "https://issuer.example",
	screen: "https://login.example",
	clients: [],
	change,
});

// The whole Core composed: a hole that shows only when every real module is composed (a dependency
// cycle, a state part no module owns) fails here, in the checks, before any harness step.
it("boots the default pattern, every module its own, claim 1 held, and stops it", async () => {
	const { names, modules, config } = await pattern(spec(), () => {});
	expect(names).toEqual(expect.arrayContaining([...features, "@mod/core-wire"]));
	const app = await assemble({ modules, config, runtime: quietRuntime() });
	try {
		await app.start();
		const held = app
			.get(promises)
			.judgment()
			.filter((j) => j.held)
			.map((j) => j.promise);
		expect(held).toContain(promiseNames.newAuthorization);
	} finally {
		await app.stop(2000);
	}
});

it("boots without a module taken out, a bridge among them, and its section", async () => {
	const { names, modules, config } = await pattern(spec(["-@mod/authorize-claims"]), () => {});
	expect(names).not.toContain("@mod/authorize-claims");
	expect(config).not.toHaveProperty("authorize-claims");
	const app = await assemble({ modules, config, runtime: quietRuntime() });
	try {
		await app.start();
	} finally {
		await app.stop(2000);
	}
});

it("refuses to take out a name not composed, or one another module needs", async () => {
	await expect(pattern(spec(["-@mod/nope"]), () => {})).rejects.toThrow(/not composed/);
	await expect(pattern(spec(["-@mod/keys"]), () => {})).rejects.toThrow(/needed/);
});
