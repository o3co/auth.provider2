import { describe, expect, it } from "vitest";
import { world } from "./fixtures/world.ts";

const keyOf = (c: { id: string; publicKey: string }) => ({
	credential: c.id,
	publicKey: c.publicKey,
});

describe("registrations", () => {
	it("makes a key usable only once its possession is shown, committed and taken in", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.regs.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const pending = w.asserting([credential]);
		expect(await w.keys.assert(pending.response, { ...pending, allow: [credential.id] })).toEqual({
			kind: "refused",
			reason: "unknown-credential",
		});
		expect(await w.keys.publicKeyOf(credential.id)).toBeUndefined();
		const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...pending });
		if (!("verification" in verified)) throw new Error("not verified");
		expect(verified.userVerified).toBe(true);
		const committed = await w.regs.commit({
			subject: "s1",
			...reserved,
			verification: verified.verification,
			decide: () => ({ digest: "d", eff: { key: keyOf(credential) }, records: [] }),
		});
		expect(committed).toEqual({ prev: 0 });
		const stepped = await w.land("s1", reserved.reservation, keyOf(credential), 0);
		expect(stepped).toMatchObject({ end: { ending: "took", op: reserved.reservation } });
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "active" });
		expect(await w.keys.publicKeyOf(credential.id)).toEqual({
			subject: "s1",
			publicKey: credential.publicKey,
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

	it("holds one pending reservation per subject, replaced by a retry or once it lapsed", async () => {
		const w = await world();
		const first = await w.regs.reserve({ subject: "s1", credential: await w.created() });
		if (!("reservation" in first)) throw new Error("not reserved");
		const other = await w.created();
		expect(await w.regs.reserve({ subject: "s1", credential: other })).toEqual({
			refused: "pending",
		});
		const retried = await w.regs.reserve({
			subject: "s1",
			credential: other,
			retrying: first.reservation,
		});
		expect(retried).toHaveProperty("reservation");
		expect(await w.regs.reserve({ subject: "s1", credential: other, retrying: "nope" })).toEqual({
			refused: "unknown",
		});
		w.advance(600_001);
		expect(await w.regs.reserve({ subject: "s1", credential: await w.created() })).toHaveProperty(
			"reservation",
		);
	});

	it("reserves a first key only where the subject holds none", async () => {
		const w = await world();
		const credential = await w.created();
		const first = await w.regs.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in first)) throw new Error("not reserved");
		await w.regs.cancel({ subject: "s1", ...first });
		await w.register("s1", false);
		expect(await w.regs.reserve({ subject: "s1", credential, first: true })).toEqual({
			refused: "held",
		});
		expect(await w.regs.reserve({ subject: "s1", credential })).toHaveProperty("reservation");
	});

	it("decides no key change while another op is open on the flow", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.regs.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const verified = await w.regs.verifyPending({
			subject: "s1",
			...reserved,
			...w.asserting([credential]),
		});
		if (!("verification" in verified)) throw new Error("not verified");
		const decide = () => ({ digest: "d", eff: { key: keyOf(credential) }, records: [] });
		const commit = () =>
			w.regs.commit({ subject: "s1", ...reserved, verification: verified.verification, decide });
		expect(await commit()).toEqual({ prev: 0 });
		expect(await commit()).toEqual({ refused: "open" });
	});

	it("refuses a credential another subject holds or reserved", async () => {
		const w = await world();
		const credential = await w.created();
		await w.regs.reserve({ subject: "s1", credential });
		expect(await w.regs.reserve({ subject: "s2", credential })).toEqual({ refused: "taken" });
	});

	it("verifies only the reserved key, before it lapses", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.regs.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const stranger = await w.created();
		const wrong = w.asserting([stranger], w.auth, stranger.id);
		expect(await w.regs.verifyPending({ subject: "s1", ...reserved, ...wrong })).toEqual({
			refused: "unknown",
		});
		const shown = w.asserting([credential]);
		expect(
			await w.regs.verifyPending({
				subject: "s1",
				...reserved,
				...shown,
				challenge: w.asserting().challenge,
			}),
		).toEqual({ refused: "challenge" });
		w.advance(600_001);
		expect(
			await w.regs.verifyPending({ subject: "s1", ...reserved, ...w.asserting([credential]) }),
		).toEqual({ refused: "expired" });
	});

	it("commits only a verified reservation, by the verification it gave", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.regs.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const decide = () => ({ digest: "d", eff: { key: keyOf(credential) }, records: [] });
		const commit = (verification: string) =>
			w.regs.commit({ subject: "s1", ...reserved, verification, decide });
		expect(await commit("v")).toEqual({ refused: "state" });
		const shown = w.asserting([credential]);
		const verified = await w.regs.verifyPending({ subject: "s1", ...reserved, ...shown });
		if (!("verification" in verified)) throw new Error("not verified");
		expect(await commit("v")).toEqual({ refused: "verification" });
		const other = await w.created();
		await expect(
			w.regs.commit({
				subject: "s1",
				...reserved,
				verification: verified.verification,
				decide: () => ({ digest: "d", eff: { key: keyOf(other) }, records: [] }),
			}),
		).rejects.toThrow(TypeError);
		expect(await commit(verified.verification)).toEqual({ prev: 0 });
	});

	it("cancels a reservation only while no op puts it on the log", async () => {
		const w = await world();
		const credential = await w.created();
		const reserved = await w.regs.reserve({ subject: "s1", credential });
		if (!("reservation" in reserved)) throw new Error("not reserved");
		const verified = await w.regs.verifyPending({
			subject: "s1",
			...reserved,
			...w.asserting([credential]),
		});
		if (!("verification" in verified)) throw new Error("not verified");
		await w.regs.commit({
			subject: "s1",
			...reserved,
			verification: verified.verification,
			decide: () => ({ digest: "d", eff: { key: keyOf(credential) }, records: [] }),
		});
		expect(await w.regs.cancel({ subject: "s1", ...reserved })).toEqual({ refused: "open" });
		expect(
			await w.regs.reserve({
				subject: "s1",
				credential: await w.created(),
				retrying: reserved.reservation,
			}),
		).toEqual({ refused: "open" });
		await w.land("s1", reserved.reservation, keyOf(credential), 0, "held");
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "ended" });
		expect(await w.regs.cancel({ subject: "s1", ...reserved })).toEqual({ cancelled: true });
		expect(w.frames.value("s1", "reservation")).toMatchObject({ state: "cancelled" });
		expect(await w.regs.cancel({ subject: "s1", ...reserved })).toEqual({ refused: "state" });
	});

	it("removes a key but the last, which only clearing removes", async () => {
		const w = await world();
		const one = await w.register();
		const decide = (removeKey: string) => () => ({ digest: "d", eff: { removeKey }, records: [] });
		const recordOf = () => {
			const kept = w.frames.value("s1", "keys") as { keys: Record<string, { credential: string }> };
			return (id: string) => Object.entries(kept.keys).find(([, k]) => k.credential === id)?.[0];
		};
		const oneRecord = recordOf()(one.credential.id) as string;
		expect(
			await w.regs.remove({
				subject: "s1",
				credential: one.credential.id,
				op: "rm1",
				decide: decide(oneRecord),
			}),
		).toEqual({ refused: "last" });
		expect(
			await w.regs.remove({
				subject: "s1",
				credential: "none",
				op: "rm1",
				decide: decide(oneRecord),
			}),
		).toEqual({ refused: "unknown" });
		expect(
			await w.clearing.clear({
				subject: "s1",
				credential: one.credential.id,
				op: "rm1",
				decide: decide(oneRecord),
			}),
		).toEqual({ prev: 1 });
	});
});
