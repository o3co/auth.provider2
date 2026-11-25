import {
	BootRefused,
	type Contribution,
	defineModule,
	isUnavailable,
	type Module,
	type Parts,
	Unavailable,
} from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { softwareAuthenticator } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import {
	heldKeys,
	type PasskeyRemoval,
	passkeyGenerations,
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

	it("leaves a removal untold where a contributor could not tell it, told again at the next settle", async () => {
		const told: string[] = [];
		let down = true;
		const failing = contributing("failing", (m) => [
			m.contribute(passkeyRemovals).by(() => ({
				removed: async (_s: string, credential: string) => {
					if (down) {
						down = false;
						throw new Unavailable("store");
					}
					told.push(credential);
				},
			})),
		]);
		const w = await world({ modules: [failing, memoryWitnessing().module] });
		const one = await w.register();
		const two = await w.register("s1", false, w.auth, w.recordOf("s1", one.credential.id));
		const k2 = w.recordOf("s1", two.credential.id);
		const removed = await w.regs.remove({
			subject: "s1",
			credential: two.credential.id,
			op: "rm1",
			decide: deciding({ removeKey: k2 }),
		});
		if (!("prev" in removed)) throw new Error(removed.refused);
		await w.land("s1", "rm1", keyStage(flow, "rm1", { credential: "-", publicKey: "-" }), 2);
		await expect(w.keys.settle("s1")).rejects.toSatisfy(isUnavailable);
		// Nothing held as told: its details stay, and the next settle tells it.
		expect(w.credentials.value(two.credential.id)).toHaveProperty("details");
		expect(await w.keys.settle("s1")).toBe(true);
		expect(told).toEqual([two.credential.id]);
		expect(w.credentials.value(two.credential.id)).not.toHaveProperty("details");
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
		const k2 = w.recordOf("s1", two.credential.id);
		const three = await w.register("s1", false, w.auth, k2);
		const k3 = w.recordOf("s1", three.credential.id);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(witnessing.marks.get("s1")).toBe(0);
		// Removing k3, which roots nothing: it is told, by whoever settles, once.
		const removed = await w.regs.remove({
			subject: "s1",
			credential: three.credential.id,
			op: "rm1",
			decide: deciding({ removeKey: k3 }),
		});
		if (!("prev" in removed)) throw new Error(removed.refused);
		await w.land("s1", "rm1", keyStage(flow, "rm1", { credential: "-", publicKey: "-" }), 3);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(await w.keys.settle("s1")).toBe(true);
		expect(told).toEqual([["s1", three.credential.id, false]]);
		expect(w.credentials.value(three.credential.id)).not.toHaveProperty("details");
		expect(witnessing.marks.get("s1")).toBe(0);
		// A boundary empties the keys and moves the generation on: the mark set for the old one goes.
		w.log.boundary(flow);
		await w.t.tend(flow);
		expect(await w.keys.settle("s1")).toBe(false);
		expect(told.slice(1)).toEqual(
			expect.arrayContaining([
				["s1", one.credential.id, true],
				["s1", two.credential.id, true],
			]),
		);
		expect(told).toHaveLength(3);
		expect(witnessing.marks.has("s1")).toBe(false);
	});

	it("tells of a key added and taken off between two settles", async () => {
		const told: string[] = [];
		const watcher = contributing("watcher", (m) => [
			m.contribute(passkeyRemovals).by(() => ({
				removed: async (_s: string, credential: string) => {
					told.push(credential);
				},
			})),
		]);
		const w = await world({ modules: [watcher] });
		await w.register();
		await w.keys.settle("s1");
		const two = await w.register("s1", false);
		const k2 = w.recordOf("s1", two.credential.id);
		const removed = await w.regs.remove({
			subject: "s1",
			credential: two.credential.id,
			op: "rm1",
			decide: deciding({ removeKey: k2 }),
		});
		if (!("prev" in removed)) throw new Error(removed.refused);
		await w.land("s1", "rm1", keyStage(flow, "rm1", { credential: "-", publicKey: "-" }), 2);
		await w.keys.settle("s1");
		expect(told).toEqual([two.credential.id]);
	});

	it("withdraws, reading the keys again, the mark of a settle that read before a boundary", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		await w.register();
		const go = witnessing.hold();
		const late = w.keys.settle("s1");
		w.log.boundary(flow);
		await w.t.tend(flow);
		expect(await w.keys.settle("s1")).toBe(false);
		go();
		await late;
		expect(witnessing.marks.has("s1")).toBe(false);
		expect(
			await w.reserve({ subject: "s1", credential: await w.created(), first: true, generation: 1 }),
		).toHaveProperty("reservation");
	});

	it("keeps the current generation's mark where a late settle's old mark lands between another's withdraw and mark", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		await w.register();
		expect(await w.keys.settle("s1")).toBe(true);
		// A settle reads the keys at generation 0; its mark waits.
		const goLate = witnessing.hold();
		const late = w.keys.settle("s1");
		w.log.boundary(flow);
		await w.t.tend(flow);
		await w.register("s1", true, w.auth, undefined, 1);
		// The new key's settle withdraws below 1, then its mark waits too.
		const goNew = witnessing.hold();
		const settled = w.keys.settle("s1");
		await new Promise((resolve) => setTimeout(resolve, 0));
		// The late mark of 0 lands first, then the new mark, then the late settle reads again.
		goLate();
		goNew();
		expect(await settled).toBe(true);
		await late;
		expect(witnessing.marks.get("s1")).toBe(1);
	});

	it("withdraws, at the next settle, a mark of an old generation a settle stopped after setting", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		await w.register();
		expect(await w.keys.settle("s1")).toBe(true);
		w.log.boundary(flow);
		await w.t.tend(flow);
		expect(await w.keys.settle("s1")).toBe(false);
		// A settle that read before the boundary set its mark, then stopped before reading again.
		await witnessing.witnessing.mark("s1", 0);
		expect(await w.keys.settle("s1")).toBe(false);
		expect(witnessing.marks.has("s1")).toBe(false);
	});

	it("answers unavailable, telling nothing, where the keys are behind what a settle saw", async () => {
		const told: string[] = [];
		const watcher = contributing("watcher", (m) => [
			m.contribute(passkeyRemovals).by(() => ({
				removed: async (_s: string, credential: string) => {
					told.push(credential);
				},
			})),
		]);
		const w = await world({ modules: [watcher] });
		await w.register();
		await w.keys.settle("s1");
		w.frames.drop("s1", "keys");
		expect(isUnavailable(await w.keys.settle("s1").catch((e) => e))).toBe(true);
		expect(told).toEqual([]);
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

	it("reads a subject's keys' credentials and the witness's mark, writing nothing", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		const held = w.app.get(heldKeys);
		expect(await held.of("s1")).toEqual({ credentials: [], marked: false });
		const one = await w.register();
		expect(await held.of("s1")).toEqual({
			credentials: [one.credential.id],
			marked: false,
		});
		// No mark is written by the read.
		expect(witnessing.marks.has("s1")).toBe(false);
		expect(Object.isFrozen((await held.of("s1")).credentials)).toBe(true);
		// A mark of a generation before the flow's reads as set until a settle withdraws it.
		await witnessing.witnessing.mark("s3", 0);
		w.frames.set("s3", "keys", { keyGeneration: 1, keys: {} });
		expect(await held.of("s3")).toEqual({ credentials: [], marked: true });
		expect(await w.keys.settle("s3")).toBe(false);
		expect(await held.of("s3")).toEqual({ credentials: [], marked: false });
		// One of this generation stays: a reservation of a first key refuses it.
		await witnessing.witnessing.mark("s4", 0);
		expect(await w.keys.settle("s4")).toBe(false);
		expect((await held.of("s4")).marked).toBe(true);
	});
});

describe("heldKeys' pending reservation", () => {
	it("reads the one reservation waiting for its possession, while it has not lapsed, and none once it took", async () => {
		const w = await world();
		const held = w.app.get(heldKeys);
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in reserved)) throw new Error(reserved.refused);
		const pending = {
			reservation: reserved.reservation,
			credential: credential.id,
			publicKey: credential.publicKey,
		};
		expect((await held.of("s1")).pending).toEqual(pending);
		// Verified, it still waits for its commit.
		const shown = w.asserting([credential]);
		await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown });
		expect((await held.of("s1")).pending).toEqual(pending);
		w.advance(10 * 60_000 + 1);
		expect((await held.of("s1")).pending).toBeUndefined();
		const other = await w.register("s2");
		expect((await held.of("s2")).pending).toBeUndefined();
		expect((await held.of("s2")).credentials).toEqual([other.credential.id]);
	});
});

describe("passkeyGenerations", () => {
	it("answers a subject's key generation as its applied state holds it, moved on by a boundary taken in", async () => {
		const w = await world();
		const generations = await w.app.get(passkeyGenerations);
		expect(await generations.generation("s1")).toBe(0);
		w.log.boundary(flow);
		// The boundary is on the log, not yet taken in: the applied state lags it.
		expect(await generations.generation("s1")).toBe(0);
		await w.t.tend(flow);
		expect(await generations.generation("s1")).toBe(1);
		expect(await generations.generation("other")).toBe(0);
	});
});
