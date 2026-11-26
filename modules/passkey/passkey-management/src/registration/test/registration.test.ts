import { takenOverAfterMs } from "@mod/approvals/testing";
import { Unavailable } from "@mod/kernel";
import { challengeInput } from "@mod/sdk-core-wire";
import { softwareAuthenticator } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { type Registered, registrationOver } from "../registration.ts";
import { sha256, stack } from "./stack.ts";

type World = Awaited<ReturnType<typeof stack>>;
const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));
const possessionOf = (r: Registered) => {
	if (r.kind !== "possession") throw new Error(r.kind === "refused" ? r.reason : r.kind);
	return r.statement;
};
/** The pending key a possession names, as the screen's `get()` is asked to name it. */
async function pendingKey(w: World, possession: string, handle: string) {
	const items = payloadOf(possession).possession;
	const pending = (await w.parts.held.of("s1")).pending;
	if (!pending) throw new Error("none pending");
	return {
		id: items.credential_id as string,
		publicKey: pending.publicKey,
		signCount: 0,
		userHandle: handle,
		backupEligible: false,
		backedUp: false,
	};
}

describe("a first key's registration after its creation", () => {
	it("reserves the key and signs its possession, then puts the change on the flow and completes it", async () => {
		const w = await stack();
		const c = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const items = payloadOf(possession).possession;
		const pending = (await w.parts.held.of("s1")).pending;
		expect(items).toMatchObject({
			creation_hash: c.hash,
			credential_id: pending?.credential,
			reservation_id: pending?.reservation,
		});
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		const finished = await w.registration.finish({ statement: possession, assertion });
		expect(finished).toMatchObject({
			kind: "completed",
			enc: expect.any(String),
			ct: expect.any(String),
		});
		expect(await w.parts.passkeys.publicKeyOf(items.credential_id)).toMatchObject({
			subject: "s1",
		});
		expect((await w.parts.held.of("s1")).pending).toBeUndefined();
		expect(w.settled).toContain("s1");
		// The register continuation the screen sent, as approvals kept it, after the creation.
		const sent = (await w.parts.approvals.keptChangeOf(sha256(possession)))?.continuation;
		expect(w.book.sent[0]?.stage.preimage?.evidence).toEqual([
			{ form: "statement", value: c.statement },
			{
				form: "continuation",
				value: JSON.stringify({ body: sent?.body, seq: 1, signature: sent?.signature }),
			},
			{ form: "statement", value: possession },
			{ form: "assertion", value: assertion },
		]);
		// Asked again, the completion kept is answered alike.
		expect(await w.registration.finish({ statement: possession, assertion })).toEqual(finished);
	});

	it("answers the same continuation again with the possession kept, signing none other", async () => {
		const w = await stack();
		const c = await w.created();
		const asked = w.continued(c, w.made(c));
		const first = possessionOf(await w.registration.register(asked));
		expect(possessionOf(await w.registration.register(asked))).toBe(first);
	});

	it("carries on, in a step run again, the very reservation its first run made, never replacing it", async () => {
		const w = await stack();
		const c = await w.created();
		let busy = true;
		const failing = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				issue: async (ask) => {
					if (!busy) return w.parts.approvals.issue(ask);
					busy = false;
					return { kind: "refused", reason: "busy" };
				},
			},
		});
		const asked = w.continued(c, w.made(c));
		await expect(failing.register(asked)).rejects.toThrow(Unavailable);
		const first = (await w.parts.held.of("s1")).pending;
		// Once the first call's hold lapsed, the same continuation runs its step again.
		w.advance(takenOverAfterMs + 1);
		const possession = possessionOf(await failing.register(asked));
		const again = (await w.parts.held.of("s1")).pending;
		expect(again).toEqual(first);
		expect(payloadOf(possession).possession.reservation_id).toBe(first?.reservation);
	});

	it("leaves the reservation a kept possession names, where a step's first run goes on late", async () => {
		const w = await stack();
		const c = await w.created();
		const asked = w.continued(c, w.made(c));
		const possession = possessionOf(await w.registration.register(asked));
		const kept = await w.parts.held.of("s1");
		// The late run: its step runs again past the call whose answer was kept.
		const kept2 = await w.parts.approvals.creationOf(c.hash);
		if (!kept2) throw new Error("no creation");
		const late = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				continue: async (q) => ({
					kind: "continued",
					seq: q.seq,
					again: false,
					result: await q.step(kept2),
				}),
			},
		});
		await late.register(asked);
		expect(await w.parts.held.of("s1")).toEqual(kept);
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		expect(await w.registration.finish({ statement: possession, assertion })).toMatchObject({
			kind: "completed",
		});
	});

	it("answers a completion kept, though the creation that made it has expired since", async () => {
		const w = await stack();
		const c = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		const finished = await w.registration.finish({ statement: possession, assertion });
		w.advance(5 * 60_000 + 10_000);
		expect(await w.parts.approvals.creationOf(c.hash)).toBeUndefined();
		expect(await w.registration.finish({ statement: possession, assertion })).toEqual(finished);
	});

	it("keeps the reservation another creation's step names with the same key, its own possession finishing", async () => {
		const w = await stack();
		const c = await w.created();
		const body = w.made(c);
		const possession = possessionOf(await w.registration.register(w.continued(c, body)));
		const pending = (await w.parts.held.of("s1")).pending;
		// The same key's response, its client data made over another creation of the same subject.
		const other = await w.created();
		const response = JSON.parse(body);
		const data = JSON.parse(Buffer.from(response.response.clientDataJSON, "base64url").toString());
		data.challenge = sha256(challengeInput(other.statement, "create"));
		response.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString("base64url");
		const relayed = possessionOf(
			await w.registration.register(w.continued(other, JSON.stringify(response))),
		);
		expect(payloadOf(relayed).possession.reservation_id).toBe(pending?.reservation);
		expect((await w.parts.held.of("s1")).pending).toEqual(pending);
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		expect(await w.registration.finish({ statement: possession, assertion })).toMatchObject({
			kind: "completed",
		});
	});

	it("keeps nothing, unavailable, where the flow is open, no receipt came, or the ring signs no more", async () => {
		const w = await stack();
		const c = await w.created();
		const open = registrationOver({
			...w.parts,
			registrations: { ...w.parts.registrations, reserve: async () => ({ refused: "open" }) },
		});
		await expect(open.register(w.continued(c, w.made(c)))).rejects.toThrow(Unavailable);
		const d = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(d, w.made(d))));
		const assertion = w.asserted(possession, await pendingKey(w, possession, d.handle));
		const none = registrationOver({
			...w.parts,
			keyChange: { ...w.parts.keyChange, change: async () => ({ kind: "took", receipts: [] }) },
		});
		await expect(none.finish({ statement: possession, assertion })).rejects.toThrow(Unavailable);
		const withdrawn = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				completeKeyChange: async () => ({ kind: "refused", reason: "withdrawn" }),
			},
		});
		await expect(withdrawn.finish({ statement: possession, assertion })).rejects.toThrow(
			Unavailable,
		);
	});

	it("refuses another key while one is pending for the subject", async () => {
		const w = await stack();
		const c = await w.created();
		possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const other = await w.created();
		const body = w.made(other, softwareAuthenticator());
		expect(await w.registration.register(w.continued(other, body))).toEqual({
			kind: "refused",
			reason: "pending",
		});
	});

	it("completes with the log's first receipt where its completion was lost after the change took", async () => {
		const w = await stack();
		const c = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		const lost = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				completeKeyChange: async () => {
					throw new Unavailable("approvals");
				},
			},
		});
		await expect(lost.finish({ statement: possession, assertion })).rejects.toThrow(Unavailable);
		const appended = w.book.records({ of: "subject", id: "s1" }).length;
		// Another assertion over the same possession is not the change the log placed: none.
		const other = w.asserted(possession, await pendingKeyOf(w, possession, c.handle));
		expect(await w.registration.finish({ statement: possession, assertion: other })).toEqual({
			kind: "refused",
			reason: "ended",
		});
		expect(await w.registration.finish({ statement: possession, assertion })).toMatchObject({
			kind: "completed",
		});
		// Asked again of the log, nothing new placed.
		expect(w.book.records({ of: "subject", id: "s1" })).toHaveLength(appended);
	});

	it("completes a change placed whose completion was lost, asked again past its creation's expiry", async () => {
		const w = await stack();
		const c = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const assertion = w.asserted(possession, await pendingKey(w, possession, c.handle));
		const lost = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				completeKeyChange: async () => {
					throw new Unavailable("approvals");
				},
			},
		});
		await expect(lost.finish({ statement: possession, assertion })).rejects.toThrow(Unavailable);
		const appended = w.book.records({ of: "subject", id: "s1" }).length;
		// Past the creation's and the possession's expiry, their records still kept.
		w.advance(5 * 60_000 + 1000);
		// Another assertion is not the change the log placed: none.
		const other = w.asserted(possession, await pendingKeyOf(w, possession, c.handle));
		expect(await w.registration.finish({ statement: possession, assertion: other })).toEqual({
			kind: "refused",
			reason: "ended",
		});
		// Its subject revoked since: refused.
		w.revoke();
		expect(await w.registration.finish({ statement: possession, assertion })).toEqual({
			kind: "refused",
			reason: "revoked",
		});
		w.revoke(false);
		expect(
			await w.parts.approvals.creationOf(payloadOf(possession).possession.creation_hash),
		).toBeUndefined();
		expect(await w.registration.finish({ statement: possession, assertion })).toMatchObject({
			kind: "completed",
		});
		expect(w.book.records({ of: "subject", id: "s1" })).toHaveLength(appended);
	});

	it("refuses a pending key's assertion whose user was not verified, whatever passkeys' section lets through", async () => {
		const w = await stack({ passkeys: { "user-verification": "preferred" } });
		const c = await w.created();
		const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c))));
		const key = await pendingKey(w, possession, c.handle);
		const unverified = w.asserted(possession, key, undefined, (f) => f & ~0x04);
		expect(await w.registration.finish({ statement: possession, assertion: unverified })).toEqual({
			kind: "refused",
			reason: "unverified",
		});
	});

	it("asks no create() for a sign-up's creation its T's sign-up does not hold", async () => {
		const w = await stack();
		const made = await w.created("s9", "sign-up");
		expect(await w.registration.register(w.continued(made, w.made(made)))).toEqual({
			kind: "refused",
			reason: "sign-up",
		});
	});

	it("refuses a subject revoked since its creation, and a passkey-add's creation no used passkey-add bases", async () => {
		const w = await stack();
		const added = await w.created("s3", "passkey-add");
		expect(await w.registration.register(w.continued(added, w.made(added)))).toEqual({
			kind: "refused",
			reason: "approver",
		});
		w.revoke();
		const later = await w.created("s2");
		expect(await w.registration.register(w.continued(later, w.made(later)))).toEqual({
			kind: "refused",
			reason: "revoked",
		});
	});
});

/** The key a possession names, read once its change took: from the keys now active. */
async function pendingKeyOf(w: World, possession: string, handle: string) {
	const id = payloadOf(possession).possession.credential_id as string;
	const key = await w.parts.passkeys.publicKeyOf(id);
	if (!key) throw new Error("not active");
	return {
		id,
		publicKey: key.publicKey,
		signCount: 1,
		userHandle: handle,
		backupEligible: false,
		backedUp: false,
	};
}
