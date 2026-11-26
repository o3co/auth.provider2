import type { Credential } from "@mod/webauthn";
import { describe, expect, it } from "vitest";
import { deciding, keyStage, world } from "./fixtures/world.ts";

const flow = { of: "subject", id: "s1" } as const;
const keyOf = (c: Credential) => ({ credential: c.id, publicKey: c.publicKey });
type World = Awaited<ReturnType<typeof world>>;

/** Verifies `reserved` by its credential and commits it, the writer keeping its stage. */
async function committed(w: World, credential: Credential, reservation: string) {
	const shown = w.asserting([credential]);
	const verified = await w.regs.verifyPending({ subject: "s1", reservation, ...shown });
	if (!("verification" in verified)) throw new Error(verified.refused);
	const stage = keyStage(flow, reservation, keyOf(credential));
	const decided = await w.regs.commit({
		subject: "s1",
		reservation,
		verification: verified.verification,
		decide: deciding({ key: keyOf(credential) }, stage),
	});
	return { stage, verification: verified.verification, decided };
}

// The 0.23 checks (操作の id の決め直し): a key change whose record is on the flow is never decided
// again under its version (~InLogKey); its retry is a new version (RegAbandon023's Retry).
describe("a key change retried after its record did not take, or was held", () => {
	it.each([
		["didNotTake", "verified", "verified"],
		["held", "held", "ended"],
	] as const)("takes as a new version, the same credential, after %s", async (_, verdict, left) => {
		const w = await world();
		const credential = await w.created();
		const first = await w.reserve({ subject: "s1", credential, first: true });
		if (!("reservation" in first)) throw new Error(first.refused);
		const v1 = await committed(w, credential, first.reservation);
		if (!("prev" in v1.decided)) throw new Error(v1.decided.refused);
		const outcome = verdict === "held" ? "took" : "didNotTake";
		await w.land("s1", first.reservation, v1.stage, v1.decided.prev, verdict, outcome);
		expect(w.frames.value("s1", "reservation")).toMatchObject({
			version: first.reservation,
			state: left,
		});
		expect(await w.keys.publicKeyOf(credential.id)).toBeUndefined();
		// Its version is not decided again: transparency's word, passed through.
		expect(
			await w.regs.commit({
				subject: "s1",
				reservation: first.reservation,
				verification: v1.verification,
				decide: deciding({ key: keyOf(credential) }, v1.stage),
			}),
		).toEqual({ refused: "ended" });
		const retried = await w.reserve({
			subject: "s1",
			credential,
			first: true,
			retrying: first.reservation,
		});
		if (!("reservation" in retried)) throw new Error(retried.refused);
		expect(retried.reservation).not.toBe(first.reservation);
		// The retry took the credential's binding over: it carries the new version.
		expect(w.credentials.value(credential.id)).toMatchObject({ version: retried.reservation });
		const v2 = await committed(w, credential, retried.reservation);
		if (!("prev" in v2.decided)) throw new Error(v2.decided.refused);
		expect(await w.land("s1", retried.reservation, v2.stage, v2.decided.prev)).toMatchObject({
			end: { ending: "took", op: retried.reservation },
		});
		expect(w.frames.value("s1", "reservation")).toMatchObject({
			version: retried.reservation,
			state: "active",
		});
		expect(w.credentials.value(credential.id)).toMatchObject({ version: retried.reservation });
		expect(await w.keys.publicKeyOf(credential.id)).toMatchObject({
			subject: "s1",
			publicKey: credential.publicKey,
		});
	});
});
