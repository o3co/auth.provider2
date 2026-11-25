import { approvals } from "@mod/approvals";
import { allowed, emptyState } from "@mod/authority-rules";
import { continuations } from "@mod/continuation-wire";
import { challengeInput, hpke } from "@mod/sdk-core-wire";
import type { Stage } from "@mod/transparency";
import { type Credential, ceremonies } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { nameOf } from "../../account.ts";
import { signUpCreations } from "../../contract.ts";
import { firstKeyWorld, opened, payloadOf, rulesOf, screen, sha256 } from "./world.ts";

describe("a sign-up's creation, as the sign-up package asks it", () => {
	it("is made for T and the new subject, named by the deployment and a mark of the subject", async () => {
		const w = await firstKeyWorld();
		const s = await screen();
		const tHash = sha256("t.of.sign-up");
		const made = await (await w.app.get(signUpCreations)).create({
			tHash,
			subject: "s-new",
			screen: { eEnc: s.eEnc, eSig: s.eSig },
			since: w.now(),
		});
		if (made.kind !== "issued") throw new Error(made.reason);
		const items = payloadOf(made.statement).creation;
		expect(items).toMatchObject({
			basis: "sign-up",
			evidence: tHash,
			subject: "s-new",
			kg: 0,
			// The deployment's name, here the mail link's host, and a mark of the subject.
			options: { user_name: nameOf(new URL(testOrigin).hostname, "s-new") },
		});
		expect(items).not.toHaveProperty("account");
		expect(payloadOf(made.statement)).toMatchObject({ e_enc: s.eEnc });
	});
});

const tItems = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "st",
	scope: "openid",
	nonce: "n",
	code_challenge: "cc",
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	jar_hash: "jh",
} as const;

type World = Awaited<ReturnType<typeof firstKeyWorld>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const client = { origin: testOrigin };

/** A T allowing a sign-up, issued to a screen, and its sign-up begun as the sign-up package's step runs it. */
async function begun() {
	const w = await firstKeyWorld();
	await w.app.start();
	const ap = await w.app.get(approvals);
	const creations = await w.app.get(signUpCreations);
	const s = await screen();
	const t = await ap.issue({
		purpose: "authorization",
		items: tItems,
		screen: { eEnc: s.eEnc, eSig: s.eSig },
		by: "src",
		continues: ["sign-up"],
	});
	if (t.kind !== "issued") throw new Error(t.reason);
	const step = await ap.continueSignUp({
		hash: t.hash,
		seq: 1,
		body: "{}",
		signature: s.signs(continuations.of("sign-up", t.hash, 1, sha256("{}"))),
		step: async (kept) => {
			const subject = (await ap.signUpSubject(kept.hash, "s-new")) ?? "s-new";
			const made = await creations.create({
				tHash: kept.hash,
				subject,
				screen: kept.screen,
				since: w.now(),
			});
			return made.kind === "issued" ? { creation: made.statement } : { refused: made.reason };
		},
	});
	if (step.kind !== "continued") throw new Error(step.reason);
	const creation = (step.result as { creation: string }).creation;
	return { w, ap, creations, s, t, creation };
}

/** The screen's create() over a creation, its register continuation `seq`, and the new key's assertion. */
async function registered(w: World, s: Screen, creation: string, seq = 1) {
	const cer = await w.app.get(ceremonies);
	const auth = softwareAuthenticator();
	const items = payloadOf(creation).creation;
	const options = cer.creation(
		sha256(challengeInput(creation, "create")),
		{ handle: items.options.user_id, name: items.options.user_name },
		[],
		"required",
	);
	const body = JSON.stringify(auth.create(options as never, client));
	const sig = s.signs(continuations.of("register", sha256(creation), seq, sha256(body)));
	const answered = await w.post("/continue", {
		statement: creation,
		stage: "register",
		seq: String(seq),
		body,
		sig,
	});
	if (answered.status !== 200) return { answered };
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
	return { answered, possession, named, assertion };
}

/** The reason the last `/continue` was refused with, as the package's log tells it. */
const continueRefusal = (w: World) =>
	w.recorded
		.lines()
		.filter((l) => l.event === "passkey-management.continue_refused")
		.at(-1)?.fields;

describe("a sign-up's first key (F1), from its T to its completion, over real sealing", () => {
	it("is registered over its creation and placed with its T before it, the rules allowing its record", async () => {
		const { w, ap, s, t, creation } = await begun();
		const k = await registered(w, s, creation);
		expect(k.answered.status).toBe(200);
		const finished = await w.post("/key/finish", {
			statement: k.possession,
			assertion: k.assertion,
		});
		expect(finished.status).toBe(200);
		const done = await opened(
			s,
			finished.json.sealed as never,
			hpke.info.completion,
			hpke.completionAad("sign-up", sha256(k.possession as string)),
		);
		expect(payloadOf(done ?? "..")).toMatchObject({
			purpose: "sign-up",
			change: { op: "add", credential_id: k.named?.credential_id, key_jkt: k.named?.key_jkt },
		});
		// Its record: T, the creation, the continuation, the possession and the assertion.
		const stage = w.book.sent.at(-1)?.stage as Stage;
		expect(stage.preimage?.evidence.map((e) => e.form)).toEqual([
			"statement",
			"statement",
			"continuation",
			"statement",
			"assertion",
		]);
		expect(stage.preimage?.evidence[0]?.value).toBe(t.statement);
		const askOf = await rulesOf(w);
		expect(allowed(askOf(stage, emptyState))).toEqual({ allowed: true });
		// With another T before it, or on a flow holding a record already, the rules refuse it.
		const other = await ap.issue({
			purpose: "authorization",
			items: tItems,
			screen: { eEnc: s.eEnc, eSig: s.eSig },
			by: "src",
			continues: ["sign-up"],
		});
		if (other.kind !== "issued") throw new Error(other.reason);
		const swapped = {
			...stage,
			preimage: {
				...stage.preimage,
				evidence: stage.preimage?.evidence.map((e, at) =>
					at === 0 ? { ...e, value: other.statement } : e,
				),
			},
		} as Stage;
		expect(allowed(askOf(swapped, emptyState))).toMatchObject({ allowed: false });
		const prior = { ...askOf(stage, emptyState), prior: [{} as never] };
		expect(allowed(prior)).toEqual({
			allowed: false,
			reason: "the flow has a record: a sign-up's key is its first",
		});
		// approvals kept the credential on T, as its completion did.
		expect(await ap.signUpOf(t.hash)).toMatchObject({
			subject: "s-new",
			credential: k.named?.credential_id,
		});
		await w.app.stop();
	});

	it("registers no second key over the same creation, its subject holding one", async () => {
		const { w, s, creation } = await begun();
		const one = await registered(w, s, creation);
		const finish = { statement: one.possession, assertion: one.assertion };
		const first = await w.post("/key/finish", finish);
		const placed = w.book.sent.length;
		const two = await registered(w, s, creation, 2);
		expect(two.answered).toEqual({ status: 400, json: { error: "access_denied" } });
		expect(continueRefusal(w)).toEqual({ stage: "register", reason: "held" });
		expect(w.book.sent).toHaveLength(placed);
		// The first finish asked again: its completion kept, alike.
		expect(await w.post("/key/finish", finish)).toEqual(first);
		await w.app.stop();
	});

	it("registers over no creation its T did not keep: another made for it, or one for another subject", async () => {
		const { w, creations, s, t } = await begun();
		for (const subject of ["s-new", "s-other"]) {
			const other = await creations.create({
				tHash: t.hash,
				subject,
				screen: { eEnc: s.eEnc, eSig: s.eSig },
				since: w.now(),
			});
			if (other.kind !== "issued") throw new Error(other.reason);
			const k = await registered(w, s, other.statement);
			expect(k.answered).toEqual({ status: 400, json: { error: "access_denied" } });
			expect(continueRefusal(w)).toEqual({ stage: "register", reason: "sign-up" });
		}
		expect(w.book.sent).toHaveLength(0);
		await w.app.stop();
	});

	it("completes a change placed whose completion was lost, past its creation's expiry, alike from then on", async () => {
		const { w, s, creation } = await begun();
		const k = await registered(w, s, creation);
		const finish = { statement: k.possession, assertion: k.assertion };
		// The possession used, then its completion's keeping falls: the key change took.
		w.statements.fallAfter(sha256(k.possession as string), 1);
		await expect(w.post("/key/finish", finish)).rejects.toThrow("fell");
		w.advance(5 * 60_000 + 1000);
		const again = await w.post("/key/finish", finish);
		expect(again.status).toBe(200);
		expect(await w.post("/key/finish", finish)).toEqual(again);
		await w.app.stop();
	});

	it("gives its completion no more once its T's record is gone", async () => {
		const { w, s, creation } = await begun();
		const k = await registered(w, s, creation);
		const finish = { statement: k.possession, assertion: k.assertion };
		const first = await w.post("/key/finish", finish);
		expect(first.status).toBe(200);
		// While its T's record holds, the completion kept is answered alike.
		expect(await w.post("/key/finish", finish)).toEqual(first);
		// Past T's life and the minute its record outlives it.
		w.advance(5 * 60_000 + 61_000);
		expect(await w.post("/key/finish", finish)).toEqual({
			status: 400,
			json: { error: "access_denied" },
		});
		await w.app.stop();
	});
});
