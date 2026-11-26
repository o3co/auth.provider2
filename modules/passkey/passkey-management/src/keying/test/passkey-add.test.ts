import { allowed, effectOf, emptyState, type FlowState, timely } from "@mod/authority-rules";
import { challengeInput, hpke } from "@mod/sdk-core-wire";
import type { Stage } from "@mod/transparency";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { opened, payloadOf, register, rulesOf, screen, sha256, withKey } from "./world.ts";

const client = { origin: testOrigin };

describe("a key a passkey-add approves, from its approval to its completion, over real sealing", () => {
	it("approves, creates, registers and completes the key, each answer opened by the screen, and the rules allow its record", async () => {
		const { w, cer, auth, key } = await withKey();
		const flow = { of: "subject", id: "s1" } as const;
		const keysBefore = w.frames.value(flow, { part: "passkeys", name: "keys" }) as FlowState;
		// The approval: a passkey-add for a new screen, approved by alice's key.
		const s = await screen();
		const started = await w.post("/approval/start", {
			purpose: "passkey-add",
			eEnc: s.eEnc,
			eSigX: s.eSigX,
			eSigY: s.eSigY,
		});
		expect(started.status).toBe(200);
		const statement = started.json.statement as string;
		const request = cer.request(sha256(challengeInput(statement, "get")), [], "required");
		const approval = JSON.stringify(auth.get(request as never, client, {}, key.id));
		const finished = await w.post("/approval/finish", { statement, assertion: approval });
		expect(finished.status).toBe(200);
		const hash = sha256(statement);
		const done = await opened(
			s,
			finished.json.sealed as never,
			hpke.info.completion,
			hpke.completionAad("passkey-add", hash),
		);
		const completion = payloadOf(done ?? "..");
		expect(completion).toMatchObject({
			purpose: "passkey-add",
			t_hash: hash,
			assertion_hash: sha256(approval),
		});
		const creation = completion.creation as string;
		// The creation names alice's verified address, masked, and bases itself on the passkey-add.
		expect(payloadOf(creation).creation).toMatchObject({
			basis: "passkey-add",
			evidence: hash,
			subject: "s1",
			account: "i***",
		});
		// The new key, made by another authenticator, registered and completed.
		const other = softwareAuthenticator();
		const added = await register(w, s, creation, other);
		const keyFinish = await w.post("/key/finish", {
			statement: added.possession,
			assertion: added.assertion,
		});
		expect(keyFinish.status).toBe(200);
		const keyDone = await opened(
			s,
			keyFinish.json.sealed as never,
			hpke.info.completion,
			hpke.completionAad("passkey-add", sha256(added.possession)),
		);
		expect(payloadOf(keyDone ?? "..")).toMatchObject({
			purpose: "passkey-add",
			change: {
				op: "add",
				credential_id: added.key.id,
				key_jkt: payloadOf(added.possession).possession.key_jkt,
			},
			receipt: "h.p.s",
		});
		// Its record, read by the rules as a monitor reads it, against the state before it.
		const stage = w.book.sent.at(-1)?.stage as Stage;
		const askOf = await rulesOf(w);
		const before: FlowState = { ...emptyState, ...keysBefore };
		const parent = Object.keys(keysBefore.keys)[0] as string;
		expect(allowed(askOf(stage, before))).toEqual({ allowed: true });
		expect(timely(askOf(stage, before), w.now())).toBe(true);
		const mark = `statement:${payloadOf(statement).sid}`;
		expect(effectOf(askOf(stage, before))).toEqual({
			key: {
				credential: added.key.id,
				publicKey: (stage.preimage?.content as { publicKey?: string } | undefined)?.publicKey,
				by: parent,
			},
			consume: [mark],
		});
		// One key from one passkey-add: with its mark consumed, the rules refuse the same record.
		expect(allowed(askOf(stage, { ...before, consumed: [mark] }))).toEqual({
			allowed: false,
			reason: "the statement is used",
		});
		await w.app.stop();
	});

	it("puts no second key on the flow from one passkey-add", async () => {
		const { w, cer, auth, key } = await withKey();
		const s = await screen();
		const started = await w.post("/approval/start", {
			purpose: "passkey-add",
			eEnc: s.eEnc,
			eSigX: s.eSigX,
			eSigY: s.eSigY,
		});
		const statement = started.json.statement as string;
		const request = cer.request(sha256(challengeInput(statement, "get")), [], "required");
		const approval = JSON.stringify(auth.get(request as never, client, {}, key.id));
		const finished = await w.post("/approval/finish", { statement, assertion: approval });
		const done = await opened(
			s,
			finished.json.sealed as never,
			hpke.info.completion,
			hpke.completionAad("passkey-add", sha256(statement)),
		);
		const creation = payloadOf(done ?? "..").creation as string;
		const one = await register(w, s, creation, softwareAuthenticator(), 1);
		await w.post("/key/finish", { statement: one.possession, assertion: one.assertion });
		const placed = w.book.sent.length;
		const two = await register(w, s, creation, softwareAuthenticator(), 2);
		expect(
			await w.post("/key/finish", { statement: two.possession, assertion: two.assertion }),
		).toEqual({
			status: 400,
			json: { error: "access_denied" },
		});
		expect(w.book.sent).toHaveLength(placed);
		// Refused by its change's decision: the passkey-add's mark is consumed.
		const refusals = w.recorded
			.lines()
			.filter((l) => l.event === "passkey-management.registration_refused");
		expect(refusals.at(-1)?.fields).toEqual({ reason: "used" });
		await w.app.stop();
	});
});
