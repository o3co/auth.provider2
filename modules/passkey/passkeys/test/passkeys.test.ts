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
import { deciding, keyStage, memoryWitnessing, world } from "./fixtures/world.ts";

const flow = { of: "subject", id: "s1" } as const;

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

	it("moves no count where another subject's record names the credential now", async () => {
		const w = await world();
		const { credential } = await w.register();
		const taken = { ...w.credentials.value(credential.id), subject: "s2" };
		w.credentials.put(credential.id, taken);
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toEqual({
			kind: "refused",
			reason: "unknown-credential",
		});
		expect(w.credentials.value(credential.id)).toEqual(taken);
	});

	it("settles from the applied state alone: removals told of every key gone, a mark withdrawn only once the generation moves", async () => {
		const told: Parameters<PasskeyRemoval["removed"]>[] = [];
		const watcher = contributing("watcher", (m) => [
			m.contribute(passkeyRemovals).by(() => ({
				removed: async (...args: Parameters<PasskeyRemoval["removed"]>) => {
					told.push(args);
				},
			})),
		]);
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [watcher, witnessing.module] });
		const one = await w.register();
		const k1 = w.recordOf("s1", one.credential.id);
		const two = await w.register("s1", false, w.auth, k1);
		const three = await w.register("s1", false);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(witnessing.marks.get("s1")).toBe(0);
		// Removing k1 takes k2, whose chain holds it: both are told, by whoever settles, once each.
		const removed = await w.regs.remove({
			subject: "s1",
			credential: one.credential.id,
			op: "rm1",
			decide: deciding({ removeKey: k1 }),
		});
		if (!("prev" in removed)) throw new Error(removed.refused);
		await w.land("s1", "rm1", keyStage(flow, "rm1", { credential: "-", publicKey: "-" }), 3);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(told).toEqual([
			["s1", one.credential.id, false],
			["s1", two.credential.id, false],
		]);
		expect(w.credentials.value(one.credential.id)).toEqual({ subject: "s1", signCount: 1 });
		expect(witnessing.marks.get("s1")).toBe(0);
		// A boundary empties the keys and moves the generation on: the mark set for the old one goes.
		w.log.boundary(flow);
		await w.t.tend(flow);
		expect(await w.keys.settle("s1")).toBe(false);
		expect(told.at(-1)).toEqual(["s1", three.credential.id, true]);
		expect(witnessing.marks.has("s1")).toBe(false);
	});

	it("withdraws no mark for state found missing, and reserves no first key beside a mark", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		witnessing.marks.set("s9", 0);
		expect(await w.keys.settle("s9")).toBe(false);
		expect(witnessing.marks.get("s9")).toBe(0);
		const reserved = await w.reserve({ subject: "s9", credential: await w.created(), first: true });
		expect(reserved).toEqual({ refused: "held" });
	});

	it("boots with the key change's writer taking registrations", async () => {
		const w = await world();
		expect(await w.app.get(registrations)).toBe(w.regs);
	});

	const refusedWith = (modules: readonly Module[]) =>
		world({ modules }).then(() => "booted", refusalOf);

	it("refuses to boot with two witnessings, or a witness and no witnessing", async () => {
		const witnessing = (name: string) =>
			contributing(name, (m) => [
				m.contribute(passkeyWitnessing).by(() => memoryWitnessing().witnessing),
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
