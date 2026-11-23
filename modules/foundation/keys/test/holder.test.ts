import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { hpke } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { type KeyHolder, keys } from "../src/contract.ts";
import { keyHolders } from "../src/holder.ts";
import keysModule from "../src/module.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const config = { ...kernelConfig(), ...keysConfig() };
const p256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" });

/** A holder of the test configuration's kids that no longer lets this Core sign or agree. */
function withdrawnHolder(): KeyHolder {
	const keys = new Map<string, ReturnType<typeof createPublicKey>>();
	const keyOf = (kid: string) => {
		const key = keys.get(kid) ?? createPublicKey(p256().privateKey);
		keys.set(kid, key);
		return key;
	};
	return {
		powers: { withdrawable: true, countedOutside: true },
		held: (kid) => ({ publicKey: keyOf(kid), signsUnder: ["ES256"], agrees: true }),
		sign: async () => ({ kind: "withdrawn" }),
		agree: async () => ({ kind: "withdrawn" }),
	};
}
const holding = (holder: KeyHolder, name = "withdrawn-holder") =>
	defineModule({ name, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(keyHolders).by(() => holder),
	]);

describe("the keys axis", () => {
	it("refuses a composition with no adapter of the keys axis, and one with two, naming none", async () => {
		const none = await assemble({ modules: [keysModule], config, runtime: quietRuntime() }).catch(
			(error: unknown) => error,
		);
		expect(BootRefused.is(none)).toBe(true);
		expect((none as BootRefused).refusals).toEqual([
			{
				where: "keys.holders",
				reason: "needs exactly one contribution (0): compose one adapter of the keys axis",
			},
		]);
		const two = await assemble({
			modules: [keysModule, testHolder(), holding(withdrawnHolder())],
			config,
			runtime: quietRuntime(),
		}).catch((error: unknown) => error);
		expect((two as BootRefused).refusals).toEqual([
			{ where: "keys.holders", reason: "needs exactly one contribution (2)" },
		]);
	});

	it("answers withdrawn, apart from a failure, where the holder no longer lets this Core sign or open, and logs it", async () => {
		const recorded = recordingLog();
		const app = await assemble({
			modules: [keysModule, holding(withdrawnHolder())],
			config,
			runtime: quietRuntime({ log: recorded.log }),
		});
		const k = app.get(keys);
		const payload = new TextEncoder().encode("{}");
		expect(await k.sign(k.prepare("authority", "JWT"), payload)).toEqual({ kind: "withdrawn" });
		expect(await k.sign(k.prepare("core", "approval+jwt"), payload)).toEqual({ kind: "withdrawn" });
		const sealed = { enc: new Uint8Array(65), ct: new Uint8Array(32) };
		sealed.enc.set(
			createPublicKey(p256().privateKey).export({ format: "der", type: "spki" }).subarray(-65),
		);
		expect(await k.open(sealed, hpke.info.firstKeyRequest, new Uint8Array())).toEqual({
			kind: "withdrawn",
		});
		expect(
			recorded
				.lines()
				.filter((line) => line.event === "keys.withdrawn")
				.map((line) => line.fields),
		).toEqual([
			{ use: "authority", kid: "test" },
			{ use: "core", kid: "core-test" },
			{ use: "sealing", kid: "seal-test" },
		]);
	});

	it("tells what its holder can do beyond signing, as the holder declares", async () => {
		const declared = await assemble({
			modules: [keysModule, holding(withdrawnHolder())],
			config,
			runtime: quietRuntime(),
		});
		expect(declared.get(keys).powers()).toEqual({ withdrawable: true, countedOutside: true });
		const local = await assemble({
			modules: [keysModule, testHolder()],
			config,
			runtime: quietRuntime(),
		});
		expect(local.get(keys).powers()).toEqual({ withdrawable: false, countedOutside: false });
	});
});
