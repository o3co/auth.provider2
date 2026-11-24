import { BootRefused, type Contribution, defineModule, type Module, type Parts } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { softwareAuthenticator } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import {
	type PasskeyRemoval,
	passkeyRemovals,
	passkeyWitnessing,
	registrations,
} from "../src/contract.ts";
import { world } from "./fixtures/world.ts";

const contributing = (
	name: string,
	build: (m: Parts<undefined>) => readonly Contribution<undefined>[],
) => defineModule({ name, replicaSafe: true, takes: [] }, build);
const refusalOf = (error: unknown) =>
	BootRefused.is(error) ? error.refusals.map((r) => r.reason).join("\n") : String(error);

describe("passkeys", () => {
	it("asserts only by a credential the request named, where it named any", async () => {
		const w = await world();
		const { credential } = await w.register();
		const named = w.asserting([credential]);
		expect(await w.keys.assert(named.response, { ...named, allow: ["other"] })).toEqual({
			kind: "refused",
			reason: "not-named",
		});
		expect(await w.keys.assert(named.response, { ...named, allow: [credential.id] })).toMatchObject(
			{
				kind: "asserted",
				subject: "s1",
			},
		);
		const unknown = w.asserting();
		expect(
			await w.keys.assert(
				{ ...(unknown.response as object), id: "AAAA" },
				{ ...unknown, allow: [] },
			),
		).toEqual({ kind: "refused", reason: "unknown-credential" });
	});

	it("requires user verification unless the operator weakens it, which breaks the promise", async () => {
		const w = await world();
		const unverifying = softwareAuthenticator({ userVerified: false });
		const loose = await world({
			section: { "user-verification": "preferred" },
			modules: [promisesModule],
		});
		await loose.register("s1", true, unverifying);
		const login = loose.asserting([], unverifying);
		expect(await loose.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
			userVerified: false,
		});
		const judged = (await loose.app.get(promises)).judgment();
		expect(judged.find((j) => j.promise === "front-compromise-new-authorization")).toMatchObject({
			held: false,
			breaking: [{ by: "passkeys", setting: "passkeys.user-verification" }],
		});
		await expect(w.register("s1", true, unverifying)).rejects.toThrow();
	});

	it("refuses an assertion whose count is not past the one kept", async () => {
		const w = await world();
		await w.register();
		const one = w.asserting();
		const two = w.asserting();
		expect(await w.keys.assert(two.response, { ...two, allow: [] })).toMatchObject({
			kind: "asserted",
		});
		expect(await w.keys.assert(one.response, { ...one, allow: [] })).toEqual({
			kind: "refused",
			reason: "sign-count",
		});
	});

	it("tells removals of a credential no more held, and settles the witness's mark", async () => {
		const told: Parameters<PasskeyRemoval["removed"]>[] = [];
		const settled: string[] = [];
		const watcher = contributing("watcher", (m) => [
			m.contribute(passkeyRemovals).by(() => ({
				removed: async (...args: Parameters<PasskeyRemoval["removed"]>) => {
					told.push(args);
				},
			})),
			m.contribute(passkeyWitnessing).by(() => ({
				settle: async (subject: string, holds: () => Promise<boolean>) => {
					settled.push(subject);
					return holds();
				},
			})),
		]);
		const w = await world({ modules: [watcher] });
		const { credential } = await w.register();
		expect(await w.keys.settle("s1", [credential.id])).toBe(true);
		expect(told).toEqual([]);
		expect(await w.keys.settle("s2", ["gone"])).toBe(false);
		expect(told).toEqual([["s2", "gone", true]]);
		expect(settled).toEqual(["s1", "s1", "s2"]);
	});

	it("reserves no first key where the witness says the subject holds one", async () => {
		const witness = contributing("witnessing", (m) => [
			m.contribute(passkeyWitnessing).by(() => ({ settle: async () => true })),
		]);
		const w = await world({ modules: [witness] });
		expect(
			await w.regs.reserve({ subject: "s1", credential: await w.created(), first: true }),
		).toEqual({ refused: "held" });
	});

	const refusedWith = (modules: readonly Module[]) =>
		world({ modules }).then(() => "booted", refusalOf);

	it("refuses to boot with two witnessings, or a witness and no witnessing", async () => {
		const witnessing = (name: string) =>
			contributing(name, (m) => [
				m.contribute(passkeyWitnessing).by(() => ({ settle: async () => false })),
			]);
		expect(await refusedWith([witnessing("a"), witnessing("b")])).toMatch(
			/more than one passkey witnessing/,
		);
		const witness = contributing("witness", (m) => [
			m.contribute(passkeyWitnesses).by(() => passkeyWitnessStandIn().witness),
		]);
		expect(await refusedWith([witness])).toMatch(/witness is composed without passkey witnessing/);
	});

	it("is taken for registering only by a module that stands on the promises", async () => {
		const silent = defineModule(
			{ name: "silent", replicaSafe: true, takes: [registrations] },
			() => [],
		);
		expect(await refusedWith([silent])).toMatch(/taken only by a module that contributes/);
	});
});
