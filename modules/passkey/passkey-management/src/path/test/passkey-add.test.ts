import { createHash, createPublicKey, verify, type webcrypto } from "node:crypto";
import {
	type Ask,
	allowed,
	type Checks,
	effectOf,
	emptyState,
	type FlowState,
	timely,
} from "@mod/authority-rules";
import { keys } from "@mod/keys";
import { challengeInput, continuation, firstKey, hpke } from "@mod/sdk-core-wire";
import type { Stage } from "@mod/transparency";
import { type Credential, ceremonies, keyThumbprint } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { firstKeyWorld, opened, payloadOf, screen, sealed, sha256 } from "./world.ts";

type World = Awaited<ReturnType<typeof firstKeyWorld>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const client = { origin: testOrigin };

/** `alice` (`s1`) holding one key, made through her first key's path over the routes. */
async function withFirstKey() {
	const w = await firstKeyWorld();
	await w.app.start();
	const s = await screen();
	const mailing = w.nextMail();
	const start = await sealed(w, s, "start", { identifier: "alice" });
	const started = await w.post("/first-key/start", start);
	const aad = firstKey.aad("start", start.nonce, s.eEnc, s.eSig);
	const sealedCode = started.json.sealed as never;
	const code = JSON.parse((await opened(s, sealedCode, hpke.info.firstKeyCode, aad)) ?? "{}").code;
	const token = ((await mailing).values.link as string).split("#")[1];
	const side = await screen();
	const mail = await sealed(w, side, "mail", { token, identifier: "alice", code });
	const creation = (await w.post("/first-key/mail", mail)).json.statement as string;
	const cer = await w.app.get(ceremonies);
	const auth = softwareAuthenticator();
	const registered = await register(w, side, creation, auth);
	await w.post("/key/finish", {
		statement: registered.possession,
		assertion: registered.assertion,
	});
	return { w, cer, auth, key: registered.key };
}

/** A new key made by `auth` over `creation`, registered as continuation `seq`, and its assertion. */
async function register(
	w: World,
	s: Screen,
	creation: string,
	auth: ReturnType<typeof softwareAuthenticator>,
	seq = 1,
) {
	const cer = await w.app.get(ceremonies);
	const items = payloadOf(creation).creation;
	const options = cer.creation(
		sha256(challengeInput(creation, "create")),
		{ handle: items.options.user_id, name: "alice" },
		[],
		"required",
	);
	const body = JSON.stringify(auth.create(options as never, client));
	const sig = s.signs(continuation.of("register", sha256(creation), seq, sha256(body)));
	const answered = await w.post("/continue", {
		statement: creation,
		stage: "register",
		seq: String(seq),
		body,
		sig,
	});
	const possession = answered.json.statement as string;
	const named = payloadOf(possession).possession;
	const key: Credential = {
		id: named.credential_id,
		publicKey: JSON.parse(body).response.publicKey ?? "",
		signCount: 0,
		userHandle: items.options.user_id,
		backupEligible: false,
		backedUp: false,
	};
	const request = cer.request(sha256(challengeInput(possession, "get")), [key], "required");
	const assertion = JSON.stringify(auth.get(request as never, client, {}));
	return { possession, assertion, key };
}

/** The rules' checks and context over this Core's ring and webauthn, as a monitor of its log reads them. */
async function rulesOf(w: World) {
	const ring = await w.app.get(keys);
	const cer = await w.app.get(ceremonies);
	const checks: Checks = {
		verifyJws: (jws, keySet) => ring.verifyJws(jws, keySet),
		verifyAssertion: cer.verifyAssertion,
		attestedKey: cer.attestedKey,
		verifyEsig: (key, input, signature) => {
			try {
				const jwk = { kty: "EC", crv: "P-256", x: key.x, y: key.y } as webcrypto.JsonWebKey;
				const publicKey = createPublicKey({ key: jwk, format: "jwk" });
				const how = { key: publicKey, dsaEncoding: "ieee-p1363" } as const;
				return verify("sha256", Buffer.from(input), how, Buffer.from(signature, "base64url"));
			} catch {
				return false;
			}
		},
		digest: (data) => createHash("sha256").update(data).digest("base64url"),
		keyThumbprint,
	};
	const context = {
		ring: ring.coreRing(ring.generation()) ?? [],
		origin: testOrigin,
		limits: {
			codeLifetime: 60,
			refreshLifetime: 86_400,
			issueWindow: 60,
			epsilon: 0,
			propagation: 0,
			retry: 0,
		},
	};
	return (stage: Stage, state: FlowState): Ask => ({
		record: stage as Ask["record"],
		preimage: stage.preimage,
		state,
		prior: [],
		checks,
		context,
	});
}

describe("a key a passkey-add approves, from its approval to its completion, over real sealing", () => {
	it("approves, creates, registers and completes the key, each answer opened by the screen, and the rules allow its record", async () => {
		const { w, cer, auth, key } = await withFirstKey();
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
		const { w, cer, auth, key } = await withFirstKey();
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
