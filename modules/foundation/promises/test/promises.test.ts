import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { promiseNames, promises, type Stance, stances } from "../src/contract.ts";
import promisesModule from "../src/module.ts";

const config = (required: readonly string[] = []) => ({
	...kernelConfig(),
	promises: { required },
});

/** A module that declares these stances. */
const declaring = (name: string, ...declared: readonly Stance[]): Module =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) =>
		declared.map((stance) => m.contribute(stances).by(() => stance)),
	);

const judged = async (modules: readonly Module[], required: readonly string[] = []) => {
	const recorded = recordingLog();
	const app = await assemble({
		modules: [promisesModule, ...modules],
		config: config(required),
		runtime: quietRuntime({ log: recorded.log }),
	});
	return { app, recorded };
};

describe("the promises and their judgment", () => {
	it("names the four promises, each one word of the vocabulary it owns", () => {
		expect(Object.values(promiseNames)).toEqual([
			"front-compromise-new-authorization",
			"front-compromise-client-token",
			"store-write",
			"core-compromise-contained",
		]);
	});

	it("holds no promise no module declares it holds", async () => {
		const { app } = await judged([]);
		expect(
			app
				.get(promises)
				.judgment()
				.every((j) => !j.held),
		).toBe(true);
	});

	it("holds a promise a module declares it holds and none declares it breaks", async () => {
		const tokens = declaring("tokens", {
			promise: promiseNames.clientToken,
			holds: true,
			by: "tokens",
		});
		const { app } = await judged([tokens]);
		const of = (name: string) =>
			app
				.get(promises)
				.judgment()
				.find((j) => j.promise === name);
		expect(of(promiseNames.clientToken)).toMatchObject({
			held: true,
			basis: "declared",
			breaking: [],
		});
		expect(of(promiseNames.newAuthorization)?.held).toBe(false);
	});

	it("breaks a promise any module declares it breaks, naming the module, the setting and why", async () => {
		const holding = declaring("tokens", {
			promise: promiseNames.newAuthorization,
			holds: true,
			by: "tokens",
		});
		const breaking = declaring("oidc", {
			promise: promiseNames.newAuthorization,
			holds: false,
			by: "oidc",
			setting: "oidc.userinfo.enabled",
			reason: "userinfo answers through the Front",
		});
		const { app } = await judged([holding, breaking]);
		expect(
			app
				.get(promises)
				.judgment()
				.find((j) => j.promise === promiseNames.newAuthorization),
		).toMatchObject({
			held: false,
			breaking: [
				{
					by: "oidc",
					setting: "oidc.userinfo.enabled",
					reason: "userinfo answers through the Front",
				},
			],
		});
	});

	it("writes one line per promise as it starts: held or not, its basis, what was not checked, and what breaks it", async () => {
		const breaking = declaring("oidc", {
			promise: promiseNames.newAuthorization,
			holds: false,
			by: "oidc",
			setting: "oidc.userinfo.enabled",
			reason: "userinfo answers through the Front",
		});
		const { app, recorded } = await judged([breaking]);
		await app.start();
		const lines = recorded.lines().filter((l) => l.event === "promises.judged");
		expect(lines).toHaveLength(4);
		expect(lines.find((l) => l.fields.promise === promiseNames.newAuthorization)).toEqual({
			level: "warn",
			event: "promises.judged",
			fields: {
				promise: promiseNames.newAuthorization,
				held: false,
				basis: "declared",
				unchecked: "operator's conditions; receivers' duties",
				breaking: "oidc: oidc.userinfo.enabled: userinfo answers through the Front",
			},
		});
		await app.stop();
	});

	it("refuses boot where a required promise does not hold, naming what breaks it", async () => {
		const breaking = declaring("client-assertion", {
			promise: promiseNames.clientToken,
			holds: false,
			by: "client-assertion",
			setting: "client-assertion.secret",
			reason: "a client secret is accepted",
		});
		const refused = await assemble({
			modules: [promisesModule, breaking],
			config: config([promiseNames.clientToken]),
			runtime: quietRuntime(),
		}).catch((e: unknown) => e);
		expect(BootRefused.is(refused)).toBe(true);
		expect((refused as BootRefused).refusals).toEqual([
			{
				where: "promises.required.0",
				reason:
					"front-compromise-client-token does not hold: client-assertion: client-assertion.secret: a client secret is accepted",
			},
		]);
	});

	it("lets a contract demand that its takers declare where they stand", async () => {
		const sign = contract<string>("keys.sign", { takersContribute: stances });
		const keys = defineModule({ name: "keys", replicaSafe: true, takes: [] }, (m) => [
			m.provide(sign).by(() => "signed"),
		]);
		const silent = defineModule({ name: "silent", replicaSafe: true, takes: [sign] });
		const refused = await assemble({
			modules: [promisesModule, keys, silent],
			config: config(),
			runtime: quietRuntime(),
		}).catch((e: unknown) => e);
		expect((refused as BootRefused).refusals).toEqual([
			{
				where: "silent",
				reason: "keys.sign is taken only by a module that contributes to promises.stances",
			},
		]);
	});
});
