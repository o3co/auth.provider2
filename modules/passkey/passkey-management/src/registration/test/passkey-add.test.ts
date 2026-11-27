import { Unavailable } from "@mod/kernel";
import { challengeInput } from "@mod/sdk-core-wire";
import { type Credential, passkeyJwk } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { type Registered, registrationOver } from "../registration.ts";
import { screen, sha256, stack } from "./stack.ts";

const payloadOf = (jws: string) =>
	JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8"));
const possessionOf = (r: Registered) => {
	if (r.kind !== "possession") throw new Error(r.kind === "refused" ? r.reason : r.kind);
	return r.statement;
};

/**
 * A subject `s1` holding a key made through its first key's path, a passkey-add approved by it, and
 * a creation for that passkey-add to the same screen, as the approval's finish makes it.
 */
async function added() {
	const w = await stack();
	const auth = softwareAuthenticator();
	const client = { origin: testOrigin };
	const c = await w.created();
	const possession = possessionOf(await w.registration.register(w.continued(c, w.made(c, auth))));
	const items = payloadOf(possession).possession;
	const pending = (await w.parts.held.of("s1")).pending;
	if (!pending) throw new Error("none pending");
	const approver: Credential = {
		id: items.credential_id,
		publicKey: pending.publicKey,
		signCount: 0,
		userHandle: c.handle,
		backupEligible: false,
		backedUp: false,
	};
	const first = await w.registration.finish({
		statement: possession,
		assertion: w.asserted(possession, approver, auth),
	});
	if (first.kind !== "completed") throw new Error(first.kind);
	/** A passkey-add approved by the first key, and a creation for it to the same screen. */
	const approved = async () => {
		const shown = screen();
		const a = await w.parts.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: shown.keys,
			by: "src",
		});
		if (a.kind !== "issued") throw new Error(a.reason);
		const request = w.parts.ceremonies.request(
			sha256(challengeInput(a.statement, "get")),
			[],
			"required",
		);
		const approval = JSON.stringify(auth.get(request as never, client, {}, approver.id));
		const used = await w.parts.approvals.use({ statement: a.statement, assertion: approval });
		if (used.kind !== "approved") throw new Error(used.reason);
		// The approving key as the Core names it (V30): the first key, the record's parent.
		const approverKey = passkeyJwk(approver.publicKey)?.jwk;
		if (!approverKey || approverKey.kty === "RSA") throw new Error("no approving key");
		const creation = await w.created("s1", "passkey-add", {
			evidence: a.hash,
			shown,
			approverKey,
		});
		return { a, approval, creation };
	};
	const { a, approval, creation } = await approved();
	const registration = (await w.parts.passkeys.publicKeyOf(approver.id))?.registration;
	/** A new key, made by another authenticator, registered over a creation as continuation `seq`. */
	const registered = async (seq = 1, by = softwareAuthenticator(), over = creation) => {
		const body = w.made(over, by);
		const possession = possessionOf(await w.registration.register(w.continued(over, body, seq)));
		const key = (await w.parts.held.of("s1")).pending;
		if (!key) throw new Error("none pending");
		const credential: Credential = {
			...approver,
			id: payloadOf(possession).possession.credential_id,
			publicKey: key.publicKey,
			userHandle: over.handle,
		};
		return { body, possession, assertion: w.asserted(possession, credential, by), credential };
	};
	return { w, a, approval, approver, creation, registration, registered, approved };
}

describe("a key a passkey-add approves", () => {
	it("is registered over its creation, and put on the flow by its approving key with its whole evidence", async () => {
		const { w, a, approval, creation, registration, registered } = await added();
		const k = await registered();
		const finished = await w.registration.finish({
			statement: k.possession,
			assertion: k.assertion,
		});
		expect(finished).toMatchObject({ kind: "completed" });
		const stage = w.book.sent.at(-1)?.stage;
		const sent = (await w.parts.approvals.keptChangeOf(sha256(k.possession)))?.continuation;
		expect(stage?.preimage).toEqual({
			v: 1,
			parent: registration,
			evidence: [
				{ form: "statement", value: a.statement },
				{ form: "assertion", value: approval },
				{ form: "statement", value: creation.statement },
				// The continuation the screen sent, as approvals kept it, in canonical JSON.
				{
					form: "continuation",
					value: JSON.stringify({ body: sent?.body, seq: 1, signature: sent?.signature }),
				},
				{ form: "statement", value: k.possession },
				{ form: "assertion", value: k.assertion },
			],
			content: { variant: "add", credential: k.credential.id, publicKey: k.credential.publicKey },
		});
		expect(sent?.body).toBe(k.body);
		// The op is the reservation the possession names.
		expect(stage?.op).toBe(payloadOf(k.possession).possession.reservation_id);
		expect(await w.parts.passkeys.publicKeyOf(k.credential.id)).toMatchObject({ subject: "s1" });
		// Asked again, the completion kept is answered alike.
		expect(
			await w.registration.finish({ statement: k.possession, assertion: k.assertion }),
		).toEqual(finished);
	});

	it("gives one key from one passkey-add: a second registered over the same creation is refused its change", async () => {
		const { w, registered } = await added();
		const one = await registered(1);
		await w.registration.finish({ statement: one.possession, assertion: one.assertion });
		const two = await registered(2);
		expect(
			await w.registration.finish({ statement: two.possession, assertion: two.assertion }),
		).toEqual({
			kind: "refused",
			reason: "used",
		});
		expect(await w.parts.passkeys.publicKeyOf(two.credential.id)).toBeUndefined();
	});

	it("completes a change placed whose completion was lost, once another passkey-add's key is reserved", async () => {
		const { w, registered, approved } = await added();
		const one = await registered();
		let lost = true;
		const falling = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				completeKeyChange: async (ask) => {
					if (!lost) return w.parts.approvals.completeKeyChange(ask);
					lost = false;
					throw new Unavailable("approvals");
				},
			},
		});
		await expect(
			falling.finish({ statement: one.possession, assertion: one.assertion }),
		).rejects.toThrow(Unavailable);
		expect(await w.parts.passkeys.publicKeyOf(one.credential.id)).toMatchObject({ subject: "s1" });
		// Another passkey-add's key is reserved meanwhile: the first's finish, asked again, still completes.
		const next = await approved();
		await registered(1, softwareAuthenticator(), next.creation);
		expect(
			await w.registration.finish({ statement: one.possession, assertion: one.assertion }),
		).toMatchObject({ kind: "completed" });
	});

	it("completes a change placed whose completion was lost, asked again past its passkey-add's and creation's expiry", async () => {
		const { w, registered } = await added();
		const one = await registered();
		const lost = registrationOver({
			...w.parts,
			approvals: {
				...w.parts.approvals,
				completeKeyChange: async () => {
					throw new Unavailable("approvals");
				},
			},
		});
		await expect(
			lost.finish({ statement: one.possession, assertion: one.assertion }),
		).rejects.toThrow(Unavailable);
		w.advance(5 * 60_000 + 1000);
		expect(
			await w.registration.finish({ statement: one.possession, assertion: one.assertion }),
		).toMatchObject({ kind: "completed" });
	});

	it("finishes no possession the creation's last continuation did not make", async () => {
		const { w, creation, registered } = await added();
		const one = await registered(1);
		// The same key sent again as the next continuation: the same reservation, another possession.
		const again = possessionOf(await w.registration.register(w.continued(creation, one.body, 2)));
		expect(again).not.toBe(one.possession);
		expect(
			await w.registration.finish({ statement: one.possession, assertion: one.assertion }),
		).toEqual({ kind: "refused", reason: "continuation" });
	});

	it("puts no key on the flow once its approving key is not the one that approved", async () => {
		const { w, registered } = await added();
		const k = await registered();
		const moved = registrationOver({
			...w.parts,
			passkeys: {
				...w.parts.passkeys,
				publicKeyOf: async (id) => {
					const key = await w.parts.passkeys.publicKeyOf(id);
					return key && { ...key, registration: "later" };
				},
			},
		});
		expect(await moved.finish({ statement: k.possession, assertion: k.assertion })).toEqual({
			kind: "refused",
			reason: "approver",
		});
	});

	it("asks no create() once its passkey-add has lapsed", async () => {
		const { w, creation } = await added();
		w.advance(5 * 60_000 + 1000);
		const body = w.made(creation);
		expect(await w.registration.register(w.continued(creation, body))).toMatchObject({
			kind: "refused",
		});
	});
});
