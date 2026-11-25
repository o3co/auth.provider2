import { createHash } from "node:crypto";
import { challengeInput, continuation, firstKey, hpke } from "@mod/sdk-core-wire";
import { type Credential, ceremonies } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { firstKeyWorld, opened, payloadOf, screen, sealed, sha256 } from "./world.ts";

describe("a first key, from its start to its completion, over real sealing", () => {
	it("starts, mails a token, creates, registers and completes the key, each answer opened by the screen", async () => {
		const w = await firstKeyWorld();
		await w.app.start();
		const s = await screen();
		// The start: its code sealed back to the screen alone, the mail sent by its job apart.
		const mailing = w.nextMail();
		const start = await sealed(w, s, "start", { identifier: "alice" });
		const started = await w.post("/first-key/start", start);
		expect(started.status).toBe(200);
		const startAad = firstKey.aad("start", start.nonce, s.eEnc, s.eSig);
		const code = JSON.parse(
			(await opened(s, started.json.sealed as never, hpke.info.firstKeyCode, startAad)) ?? "{}",
		).code as string;
		expect(code).toMatch(/^[0-9]{8}$/);
		const message = await mailing;
		expect(message).toMatchObject({ purpose: "first-key", to: "inbox-of-alice" });
		const link = message.values.link as string;
		expect(link.startsWith(`${testOrigin}/first-key#`)).toBe(true);
		const token = link.split("#")[1] as string;

		// The mail's side: its creation, bound to the token and to the very request the Core opened.
		const side = await screen();
		const request = await sealed(w, side, "mail", { token, identifier: "alice", code });
		const answered = await w.post("/first-key/mail", request);
		expect(answered.status).toBe(200);
		const creation = answered.json.statement as string;
		const items = payloadOf(creation).creation;
		expect(items).toMatchObject({
			subject: "s1",
			kg: 0,
			evidence: sha256(firstKey.evidenceInput(token)),
			// The very request the Core opened: SHA-256 of its `enc` then its `ct`, as sent.
			ct_hash: createHash("sha256")
				.update(Buffer.from(request.enc, "base64url"))
				.update(Buffer.from(request.ct, "base64url"))
				.digest("base64url"),
		});

		// The registration: create(), its continuation, then the new key's get() over the possession.
		const cer = await w.app.get(ceremonies);
		const auth = softwareAuthenticator();
		const client = { origin: testOrigin };
		const challenge = sha256(challengeInput(creation, "create"));
		const options = cer.creation(
			challenge,
			{ handle: items.options.user_id, name: "alice" },
			[],
			"required",
		);
		const body = JSON.stringify(auth.create(options as never, client));
		const hash = sha256(creation);
		const registered = await w.post("/continue", {
			statement: creation,
			stage: "register",
			seq: "1",
			body,
			sig: side.signs(continuation.of("register", hash, 1, sha256(body))),
		});
		expect(registered.status).toBe(200);
		const possession = registered.json.statement as string;
		const named = payloadOf(possession).possession;
		const key: Credential = {
			id: named.credential_id,
			publicKey: JSON.parse(body).response.publicKey ?? "",
			signCount: 0,
			userHandle: items.options.user_id,
			backupEligible: false,
			backedUp: false,
		};
		const request2 = cer.request(sha256(challengeInput(possession, "get")), [key], "required");
		const assertion = JSON.stringify(auth.get(request2 as never, client, {}));
		const finished = await w.post("/key/finish", { statement: possession, assertion });
		expect(finished.status).toBe(200);
		const completion = await opened(
			side,
			(finished.json.sealed ?? {}) as never,
			hpke.info.completion,
			hpke.completionAad("first-key", sha256(possession)),
		);
		expect(payloadOf(completion ?? "..")).toMatchObject({
			purpose: "first-key",
			change: { op: "add", credential_id: named.credential_id, key_jkt: named.key_jkt },
			receipt: "h.p.s",
		});
		// The key is on the subject's flow, its stage's preimage the creation, possession and assertion.
		const [placed] = w.book.sent;
		expect(placed?.stage.preimage?.evidence.map((e) => e.value)).toEqual([
			creation,
			possession,
			assertion,
		]);
		// Started again, the subject holding a key now gets no mail.
		const again = await sealed(w, await screen(), "start", { identifier: "alice" });
		expect((await w.post("/first-key/start", again)).status).toBe(200);
		await w.app.stop();
		expect(w.sent).toHaveLength(1);
	});

	it("refuses in one word a start sealed under another nonce, or to another key, mailing nothing", async () => {
		const w = await firstKeyWorld();
		await w.app.start();
		const s = await screen();
		const start = await sealed(w, s, "start", { identifier: "alice" });
		const other = await sealed(w, s, "start", { identifier: "alice" });
		// Its sealing moved to another nonce: it does not open, and is refused in one word.
		const moved = await w.post("/first-key/start", { ...start, nonce: other.nonce });
		expect(moved).toEqual({ status: 400, json: { error: "access_denied" } });
		const elsewhere = await screen();
		const swapped = await w.post("/first-key/start", { ...other, eEnc: elsewhere.eEnc });
		expect(swapped).toEqual({ status: 400, json: { error: "access_denied" } });
		await w.app.stop();
		expect(w.sent).toEqual([]);
	});
});
