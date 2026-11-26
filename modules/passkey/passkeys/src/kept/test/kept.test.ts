import {
	type Contribution,
	defineModule,
	isUnavailable,
	type Parts,
	Unavailable,
} from "@mod/kernel";
import type { Credential } from "@mod/webauthn";
import { describe, expect, it } from "vitest";
import { deciding, keyStage, memoryWitnessing, world } from "../../../test/fixtures/world.ts";
import { heldKeys, type PasskeyRemoval, passkeyRemovals } from "../../contract.ts";

const flow = { of: "subject", id: "s1" } as const;
const keyOf = (c: Credential) => ({ credential: c.id, publicKey: c.publicKey });

const contributing = (
	name: string,
	build: (m: Parts<undefined>) => readonly Contribution<undefined>[],
) => defineModule({ name, replicaSafe: true, takes: [] }, build);

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

	it("answers no assertion whose key was registered again between its verification and its answer", async () => {
		const w = await world();
		await w.register();
		const two = await w.register("s1", false);
		await w.keys.settle("s1");
		const first = w.recordOf("s1", two.credential.id);
		const k1 = Object.keys(
			(w.frames.value("s1", "keys") as { keys: Record<string, unknown> }).keys,
		).find((k) => k !== first) as string;
		const login = w.asserting([two.credential]);
		// Between its verification and its answer, the key is removed and its credential registered again.
		w.credentials.beforeChange(async () => {
			await w.regs.remove({
				subject: "s1",
				credential: two.credential.id,
				op: "rm1",
				decide: deciding({ removeKey: first }),
			});
			await w.land("s1", "rm1", keyStage(flow, "rm1", keyOf(two.credential)), 2);
			await w.keys.settle("s1");
			const reserved = await w.reserve({ subject: "s1", credential: two.credential });
			if (!("reservation" in reserved)) throw new Error(reserved.refused);
			const shown = w.asserting([two.credential]);
			const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown });
			if (!("verification" in verified)) throw new Error(verified.refused);
			const again = { ...reserved, ...verified };
			const key = keyOf(two.credential);
			const stage = keyStage(flow, again.reservation, key);
			const committed = await w.regs.commit({
				subject: "s1",
				...again,
				decide: deciding({ key: { ...key, by: k1 } }, stage),
			});
			if (!("prev" in committed)) throw new Error(committed.refused);
			await w.land("s1", again.reservation, stage, committed.prev);
		});
		const asserted = await w.keys.assert(login.response, { ...login, allow: [] });
		const now = (await w.keys.publicKeyOf(two.credential.id))?.registration;
		expect(now).toBeDefined();
		expect(now).not.toBe(first);
		// The credential's record moved meanwhile: the count is not moved over it, and the assertion is
		// refused, never answered with the later registration.
		expect(asserted).toEqual({ kind: "refused", reason: "raced" });
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
