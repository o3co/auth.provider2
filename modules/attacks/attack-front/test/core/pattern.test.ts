import { wireCertificates } from "@mod/front-relay/testing";
import { assemble } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { promiseNames, promises } from "@mod/promises";
import { afterAll, beforeAll, expect, it } from "vitest";
import { readyWithinMs } from "./launch.ts";
import { features, pattern } from "./pattern.ts";

let certificates: Awaited<ReturnType<typeof wireCertificates>>;
beforeAll(async () => {
	certificates = await wireCertificates();
	// The whole Core's modules imported once, cold, in the setup: a test then times its boot alone.
	await pattern(spec(), () => {});
}, readyWithinMs + 10_000);
afterAll(() => certificates?.remove());

const spec = (change: readonly string[] = [], required: readonly string[] = []) => ({
	certificates,
	origin: "https://issuer.example",
	screen: "https://login.example",
	clients: [],
	change,
	required,
});

// The whole Core composed: a hole that shows only when every real module is composed (a dependency
// cycle, a state part no module owns) fails here, in the checks, before any harness step.
it("boots the default pattern, every module its own, claims 1 and 2 held, and stops it", async () => {
	const { names, modules, config } = await pattern(spec(), () => {});
	expect(names).toEqual(
		expect.arrayContaining([...features, "@mod/core-wire", "@mod/refresh", "@mod/refresh-store"]),
	);
	const app = await assemble({ modules, config, runtime: quietRuntime() });
	try {
		await app.start();
		const held = app
			.get(promises)
			.judgment()
			.filter((j) => j.held)
			.map((j) => j.promise);
		expect(held).toEqual(
			expect.arrayContaining([promiseNames.newAuthorization, promiseNames.clientToken]),
		);
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

it("holds no-client-subject-token where client-credentials is not composed, and boots with it required", async () => {
	const without = await pattern(
		spec(["-@mod/client-credentials"], [promiseNames.noClientSubjectToken]),
		() => {},
	);
	expect(without.names).not.toContain("@mod/client-credentials");
	expect(without.names).toEqual(expect.arrayContaining(["@mod/code-grant", "@mod/refresh"]));
	const app = await assemble({
		modules: without.modules,
		config: without.config,
		runtime: quietRuntime(),
	});
	try {
		await app.start();
		const judged = app.get(promises).judgment();
		expect(judged.find((j) => j.promise === promiseNames.noClientSubjectToken)?.held).toBe(true);
	} finally {
		await app.stop(2000);
	}
	// With client-credentials composed, a client takes a token of its own subject: required, boot is refused.
	const withIt = await pattern(spec([], [promiseNames.noClientSubjectToken]), () => {});
	await expect(
		assemble({ modules: withIt.modules, config: withIt.config, runtime: quietRuntime() }),
	).rejects.toMatchObject({
		refusals: expect.arrayContaining([
			expect.objectContaining({ where: expect.stringMatching(/^promises\.required/) }),
		]),
	});
});
