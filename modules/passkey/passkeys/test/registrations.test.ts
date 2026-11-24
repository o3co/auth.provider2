import { isUnavailable } from "@mod/kernel";
import type { Credential } from "@mod/webauthn";
import { describe, expect, it } from "vitest";
import { deciding, keyStage, world } from "./fixtures/world.ts";

const flow = { of: "subject", id: "s1" } as const;
const keyOf = (c: Credential) => ({ credential: c.id, publicKey: c.publicKey });
type World = Awaited<ReturnType<typeof world>>;

/** A reservation of a new credential of s1's, verified. */
async function verifiedIn(w: World, credential?: Credential) {
	const c = credential ?? (await w.created());
	const reserved = await w.reserve({ subject: "s1", credential: c, first: true });
	if (!("reservation" in reserved)) throw new Error(reserved.refused);
	const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...w.asserting([c]) });
	if (!("verification" in verified)) throw new Error(verified.refused);
	return { credential: c, ...reserved, ...verified };
}

describe("registrations", () => {
	it("makes a key usable only once its possession is shown, committed and taken in", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const pending = w.asserting([credential]);
		expect(await w.keys.assert(pending.response, { ...pending, allow: [credential.id] })).toEqual({
			kind: "refused",
			reason: "unknown-credential",
		});
		expect(await w.keys.publicKeyOf(credential.id)).toBeUndefined();
		const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...pending });
		if (!("verification" in verified)) throw new Error("not verified");
		const stage = keyStage(flow, reserved.reservation, keyOf(credential));
		const committed = await w.regs.commit({
			subject: "s1",
			...reserved,
			verification: verified.verification,
			decide: deciding({ key: keyOf(credential) }, stage),
		});
		expect(committed).toEqual({ prev: 0 });
		// The writer's own record of the kind is kept in the same write, for a resend.
		expect(w.frames.value("s1", "preimage", "writer")).toEqual(stage);
		const stepped = await w.land("s1", reserved.reservation, stage, 0);
		expect(stepped).toMatchObject({ end: { ending: "took", op: reserved.reservation } });
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "active" });
		// With its registration's record, the key's id in the flow's state.
		const held = w.frames.value("s1", "keys") as { keys: Record<string, { credential: string }> };
		const [registration] =
			Object.entries(held.keys).find(([, k]) => k.credential === credential.id) ?? [];
		expect(registration).toBeDefined();
		expect(await w.keys.publicKeyOf(credential.id)).toEqual({
			subject: "s1",
			publicKey: credential.publicKey,
			registration,
		});
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toEqual({
			kind: "asserted",
			subject: "s1",
			credential: credential.id,
			userVerified: true,
			backupEligible: false,
		});
	});

	it("lets another replica resend a committed key change from the writer's record", async () => {
		const w = await world();
		const r = await verifiedIn(w);
		const stage = keyStage(flow, r.reservation, keyOf(r.credential));
		await w.regs.commit({
			subject: "s1",
			...r,
			decide: deciding({ key: keyOf(r.credential) }, stage),
		});
		w.frames.at(10_000);
		expect(await w.t.tend(flow)).toMatchObject({ did: "tookOver", answer: { result: "accepted" } });
	});

	it("releases a committed reservation for good once its op is abandoned", async () => {
		const w = await world();
		const r = await verifiedIn(w);
		await w.regs.commit({ subject: "s1", ...r, decide: deciding({ key: keyOf(r.credential) }) });
		w.frames.at(10_000);
		expect(await w.t.tend(flow)).toMatchObject({ did: "marked" });
		expect(await w.t.tend(flow)).toMatchObject({ did: "abandonment" });
		w.log.judge(flow, 1, "verified");
		await w.t.tend(flow);
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "ended" });
	});

	it("holds one pending reservation per subject, replaced by a retry or once it lapsed", async () => {
		const w = await world();
		const first = await w.reserve({ subject: "s1", credential: await w.created() });
		if (!("reservation" in first)) throw new Error("not reserved");
		const other = await w.created();
		expect(await w.reserve({ subject: "s1", credential: other })).toEqual({ refused: "pending" });
		const retried = await w.reserve({
			subject: "s1",
			credential: other,
			retrying: first.reservation,
		});
		expect(retried).toHaveProperty("reservation");
		expect(await w.reserve({ subject: "s1", credential: other, retrying: "nope" })).toEqual({
			refused: "unknown",
		});
		w.advance(600_001);
		expect(await w.reserve({ subject: "s1", credential: await w.created() })).toHaveProperty(
			"reservation",
		);
		// The credentials of the ones replaced, never active, are free for another subject.
		expect(await w.reserve({ subject: "s2", credential: other })).toHaveProperty("reservation");
	});

	it("lets one of two first registrations racing through, the other finding it pending", async () => {
		const w = await world();
		const [a, b] = [await w.created(), await w.created()];
		const raced = await Promise.all([
			w.reserve({ subject: "s1", credential: a, first: true }),
			w.reserve({ subject: "s1", credential: b, first: true }),
		]);
		expect(raced.filter((r) => "reservation" in r)).toHaveLength(1);
		expect(raced.filter((r) => "refused" in r)).toEqual([{ refused: "pending" }]);
		// The loser leaves no binding: another subject may take its credential.
		const loser = "reservation" in raced[0] ? b : a;
		expect(await w.reserve({ subject: "s2", credential: loser })).toHaveProperty("reservation");
	});

	it("reserves a first key only where the subject holds none, under the generation its approval names", async () => {
		const w = await world();
		const credential = await w.created();
		expect(await w.reserve({ subject: "s1", credential, generation: 1 })).toEqual({
			refused: "fenced",
		});
		await w.register("s1", true);
		expect(await w.reserve({ subject: "s1", credential, first: true })).toEqual({
			refused: "held",
		});
		expect(await w.reserve({ subject: "s1", credential })).toHaveProperty("reservation");
	});

	it("refuses a credential another subject holds or reserved, until its reservation is cancelled", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		expect(await w.reserve({ subject: "s2", credential })).toEqual({ refused: "taken" });
		await w.regs.cancel({ subject: "s1", ...reserved });
		expect(await w.reserve({ subject: "s2", credential })).toHaveProperty("reservation");
	});

	it("never lowers a count nor overwrites the details kept, whatever a reserve that loses", async () => {
		const w = await world();
		const { credential } = await w.register();
		const login = w.asserting();
		await w.keys.assert(login.response, { ...login, allow: [] });
		const kept = w.credentials.value(credential.id);
		expect(kept).toMatchObject({ subject: "s1", signCount: 2 });
		expect(await w.reserve({ subject: "s1", credential })).toEqual({ refused: "taken" });
		const lied = { ...credential, userHandle: "AAAA", signCount: 0 };
		const other = await w.reserve({ subject: "s2", credential: lied });
		expect(other).toEqual({ refused: "taken" });
		expect(w.credentials.value(credential.id)).toEqual(kept);
		// A retry of a pending key under the same credential leaves the count where it is.
		const pending = await w.created();
		const first = await w.reserve({ subject: "s1", credential: pending });
		if (!("reservation" in first)) throw new Error("not reserved");
		w.credentials.put(pending.id, { ...w.credentials.value(pending.id), signCount: 7 });
		const retried = await w.reserve({
			subject: "s1",
			credential: pending,
			retrying: first.reservation,
		});
		expect(retried).toHaveProperty("reservation");
		expect(w.credentials.value(pending.id)).toMatchObject({ signCount: 7 });
	});

	it("verifies only the reserved key, before it lapses, and answers the same response alike", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const stranger = await w.created();
		const wrong = w.asserting([stranger], w.auth, stranger.id);
		expect(await w.regs.verifyPending({ subject: "s1", ...reserved, ...wrong })).toEqual({
			refused: "unknown",
		});
		const shown = w.asserting([credential]);
		const elsewhere = { ...shown, challenge: w.asserting().challenge };
		expect(await w.regs.verifyPending({ subject: "s1", ...reserved, ...elsewhere })).toEqual({
			refused: "challenge",
		});
		const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown });
		expect(verified).toHaveProperty("verification");
		expect(await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown })).toEqual(verified);
		w.advance(600_001);
		expect(
			await w.regs.verifyPending({ subject: "s1", ...reserved, ...w.asserting([credential]) }),
		).toEqual({ refused: "expired" });
	});

	it("commits only a verified reservation, by the verification it gave, registering its key", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const decide = deciding({ key: keyOf(credential) });
		const commit = (verification: string) =>
			w.regs.commit({ subject: "s1", ...reserved, verification, decide });
		expect(await commit("v")).toEqual({ refused: "state" });
		const verified = await w.regs.verifyPending({
			subject: "s1",
			...reserved,
			...w.asserting([credential]),
		});
		if (!("verification" in verified)) throw new Error("not verified");
		expect(await commit("v")).toEqual({ refused: "verification" });
		await expect(
			w.regs.commit({
				subject: "s1",
				...reserved,
				...verified,
				decide: deciding({ key: keyOf(await w.created()) }),
			}),
		).rejects.toThrow(TypeError);
		// A first key is approved by none, and a registration removes nothing.
		for (const eff of [
			{ key: { ...keyOf(credential), by: "k0" } },
			{ key: keyOf(credential), removeKey: "k0" },
		])
			await expect(
				w.regs.commit({ subject: "s1", ...reserved, ...verified, decide: deciding(eff) }),
			).rejects.toThrow(TypeError);
		expect(await commit(verified.verification)).toEqual({ prev: 0 });
		expect(await commit(verified.verification)).toEqual({ refused: "open" });
	});

	it("cancels, retries or replaces a lapsed reservation only while no op puts it on the log", async () => {
		const w = await world();
		const r = await verifiedIn(w);
		await w.regs.commit({ subject: "s1", ...r, decide: deciding({ key: keyOf(r.credential) }) });
		expect(await w.regs.cancel({ subject: "s1", ...r })).toEqual({ refused: "open" });
		const next = await w.created();
		expect(await w.reserve({ subject: "s1", credential: next, retrying: r.reservation })).toEqual({
			refused: "open",
		});
		expect(w.credentials.value(next.id)).not.toHaveProperty("subject");
		w.advance(600_001);
		expect(await w.reserve({ subject: "s1", credential: next })).toEqual({ refused: "open" });
		await w.land(
			"s1",
			r.reservation,
			keyStage(flow, r.reservation, keyOf(r.credential)),
			0,
			"held",
		);
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "ended" });
		expect(await w.regs.cancel({ subject: "s1", ...r })).toEqual({ cancelled: true });
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "cancelled" });
		expect(await w.regs.cancel({ subject: "s1", ...r })).toEqual({ refused: "state" });
	});

	it("removes no key that would leave the subject none, counting the keys its chain takes too", async () => {
		const w = await world();
		const one = await w.register();
		const k1 = w.recordOf("s1", one.credential.id);
		const remove = (credential: string, op = "rm1") =>
			w.regs.remove({
				subject: "s1",
				credential,
				op,
				decide: deciding({ removeKey: w.recordOf("s1", credential) }),
			});
		expect(await remove(one.credential.id)).toEqual({ refused: "last" });
		expect(await remove("none")).toEqual({ refused: "unknown" });
		const two = await w.register("s1", false, w.auth, k1);
		// k2 hangs from k1: removing k1 takes both.
		expect(await remove(one.credential.id)).toEqual({ refused: "last" });
		const k2 = w.recordOf("s1", two.credential.id);
		const rm2 = await remove(two.credential.id, "rm2");
		expect(rm2).toEqual({ prev: 2 });
		await w.land("s1", "rm2", keyStage(flow, "rm2", keyOf(two.credential)), 2);
		expect(w.recordOf("s1", two.credential.id)).toBeUndefined();
		expect(k2).toBeDefined();
		// Every key but the first hangs from it: the first goes only with all.
		const three = await w.register("s1", false);
		expect(await remove(one.credential.id, "rm3")).toEqual({ refused: "last" });
		const pending = await w.reserve({ subject: "s1", credential: await w.created() });
		if (!("reservation" in pending)) throw new Error("not reserved");
		expect(await remove(three.credential.id, pending.reservation)).toEqual({ refused: "op" });
		expect(await remove(three.credential.id, "rm3")).toEqual({ prev: 4 });
	});

	it("lets no late release of an old reservation unbind a newer one", async () => {
		const w = await world();
		const credential = await w.created();
		const first = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in first)) throw new Error("not reserved");
		// Between the cancel's check and its release, the same credential is reserved and registered.
		w.credentials.beforeChange(async () => {
			const again = await verifiedIn(w, credential);
			const stage = keyStage(flow, again.reservation, keyOf(credential));
			const committed = await w.regs.commit({
				subject: "s1",
				...again,
				decide: deciding({ key: keyOf(credential) }, stage),
			});
			if (!("prev" in committed)) throw new Error(committed.refused);
			await w.land("s1", again.reservation, stage, committed.prev);
		});
		expect(await w.regs.cancel({ subject: "s1", ...first })).toEqual({ cancelled: true });
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
			subject: "s1",
		});
	});

	it("lets no reserve racing for the same credential take the binding its winner holds", async () => {
		const w = await world();
		const credential = await w.created();
		const raced = await Promise.all([
			w.reserve({ subject: "s1", credential, first: true }),
			w.reserve({ subject: "s1", credential, first: true }),
		]);
		const won = raced.find((r) => "reservation" in r);
		if (!won || !("reservation" in won)) throw new Error("none reserved");
		expect(raced.filter((r) => "refused" in r)).toHaveLength(1);
		const verified = await w.regs.verifyPending({
			subject: "s1",
			...won,
			...w.asserting([credential]),
		});
		if (!("verification" in verified)) throw new Error(verified.refused);
		const stage = keyStage(flow, won.reservation, keyOf(credential));
		const committed = await w.regs.commit({
			subject: "s1",
			...won,
			...verified,
			decide: deciding({ key: keyOf(credential) }, stage),
		});
		if (!("prev" in committed)) throw new Error(committed.refused);
		await w.land("s1", won.reservation, stage, committed.prev);
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
		});
	});

	it("hands back the binding a retry took over where its reservation is not written", async () => {
		const w = await world();
		const r = await verifiedIn(w);
		const stage = keyStage(flow, r.reservation, keyOf(r.credential));
		await w.regs.commit({
			subject: "s1",
			...r,
			decide: deciding({ key: keyOf(r.credential) }, stage),
		});
		const retried = await w.reserve({
			subject: "s1",
			credential: r.credential,
			first: true,
			retrying: r.reservation,
		});
		expect(retried).toEqual({ refused: "open" });
		expect(w.credentials.value(r.credential.id)).toMatchObject({ version: r.reservation });
		await w.land("s1", r.reservation, stage, 0);
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
		});
	});

	it("never releases the binding of a credential once active", async () => {
		const w = await world();
		await w.register();
		const two = await w.register("s1", false);
		await w.keys.settle("s1");
		const k2 = w.recordOf("s1", two.credential.id);
		await w.regs.remove({
			subject: "s1",
			credential: two.credential.id,
			op: "rm1",
			decide: deciding({ removeKey: k2 }),
		});
		await w.land("s1", "rm1", keyStage(flow, "rm1", keyOf(two.credential)), 2);
		await w.keys.settle("s1");
		const again = await w.reserve({ subject: "s1", credential: two.credential });
		if (!("reservation" in again)) throw new Error(again.refused);
		await w.regs.cancel({ subject: "s1", ...again });
		expect(await w.reserve({ subject: "s2", credential: two.credential })).toEqual({
			refused: "taken",
		});
	});

	it("saves a verified count when sent again, and answers alike only the same response and challenge", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const shown = w.asserting([credential]);
		w.credentials.failNextChange();
		const failed = await w.regs
			.verifyPending({ subject: "s1", ...reserved, ...shown })
			.catch((e) => e);
		expect(isUnavailable(failed)).toBe(true);
		expect(w.credentials.value(credential.id)).toMatchObject({ signCount: 0 });
		const again = await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown });
		expect(again).toHaveProperty("verification");
		expect(w.credentials.value(credential.id)).toMatchObject({ signCount: 1 });
		const elsewhere = { ...shown, challenge: w.asserting().challenge };
		// Another challenge with the same response is checked again, never answered from before.
		expect(await w.regs.verifyPending({ subject: "s1", ...reserved, ...elsewhere })).toEqual({
			refused: "challenge",
		});
	});

	it("is unavailable, never a refusal, where the credential store cannot tell", async () => {
		const w = await world();
		await w.register();
		w.credentials.fail(true);
		const login = w.asserting();
		const failed = await w.keys.assert(login.response, { ...login, allow: [] }).catch((e) => e);
		expect(isUnavailable(failed)).toBe(true);
		const reserve = await w
			.reserve({ subject: "s1", credential: await w.created() })
			.catch((e) => e);
		expect(isUnavailable(reserve)).toBe(true);
	});
});
