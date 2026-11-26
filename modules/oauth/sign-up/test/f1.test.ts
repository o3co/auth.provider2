import { continuations } from "@mod/continuation-wire";
import { checkField } from "@mod/front-core-codec";
import { overHttp, requests } from "@mod/front-core-wire";
import { challengeInput, hpke } from "@mod/sdk-core-wire";
import { type Credential, ceremonies } from "@mod/webauthn";
import { softwareAuthenticator, testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { f1World, payloadOf, screen, sha256 } from "./fixtures/world.ts";

// F1 end to end, over the modules composed: a person with no passkey starts a login, signs up at
// `/continue`'s stage `sign-up`, registers the key its creation is for, and finishes the login with it.

const at = { origin: testOrigin };
const jarOf = (now: number, over: Record<string, string> = {}) => {
	const claims = {
		iss: "c1",
		aud: "https://issuer.example",
		jti: "j1",
		exp: Math.floor(now / 1000) + 300,
		client_id: "c1",
		redirect_uri: "https://rp.example/cb",
		response_type: "code",
		response_mode: "form_post",
		state: "st",
		scope: "read",
		nonce: "n",
		code_challenge: "c".repeat(43),
		code_challenge_method: "S256",
		dpop_jkt: "jkt",
		...over,
	};
	return `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c1`;
};

describe("a person's sign-up (F1), from the login's start to its finish", () => {
	it("makes a new subject and its first key under T, and finishes the login with that key alone", async () => {
		const w = await f1World();
		await w.app.start();
		const s = await screen();
		const cer = await w.app.get(ceremonies);
		const auth = softwareAuthenticator();
		// ② The login's start: T, and the screen may offer create().
		const started = await w.post(overHttp.operations.loginStart.path, {
			clientId: "c1",
			request: jarOf(w.now()),
			eEnc: s.eEnc,
			eSigX: s.eSigX,
			eSigY: s.eSigY,
		});
		expect(started).toMatchObject({ status: 200, json: { create: true } });
		const t = started.json.statement as string;
		const tHash = sha256(t);
		// T's sign-up at `/continue`: the creation, for the subject the ledger made under T's hash.
		const signUpAsk = {
			statement: t,
			stage: "sign-up",
			seq: "1",
			body: "{}",
			sig: s.signs(continuations.of("sign-up", tHash, 1, sha256("{}"))),
		};
		const signedUp = await w.post("/continue", signUpAsk);
		expect(signedUp.status).toBe(200);
		// The same continuation again: the same creation, and no second subject made.
		expect(await w.post("/continue", signUpAsk)).toEqual(signedUp);
		const creation = signedUp.json.statement as string;
		const items = payloadOf(creation).creation;
		expect(items).toMatchObject({ basis: "sign-up", evidence: tHash, subject: "s-1" });
		expect([...w.made.entries()]).toEqual([[tHash, "s-1"]]);
		// Its key registered over the creation: the register continuation, then the key's finish.
		const options = cer.creation(
			sha256(challengeInput(creation, "create")),
			{ handle: items.options.user_id, name: items.options.user_name },
			[],
			"required",
		);
		const body = JSON.stringify(auth.create(options as never, at));
		const registered = await w.post("/continue", {
			statement: creation,
			stage: "register",
			seq: "1",
			body,
			sig: s.signs(continuations.of("register", sha256(creation), 1, sha256(body))),
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
		const asserting = (statement: string) =>
			JSON.stringify(
				auth.get(
					cer.request(sha256(challengeInput(statement, "get")), [key], "required") as never,
					at,
					{},
				),
			);
		const keyed = await w.post("/key/finish", {
			statement: possession,
			assertion: asserting(possession),
		});
		expect(keyed.status).toBe(200);
		// T is used by that key alone: another authenticator's assertion over it finishes nothing.
		const stranger = softwareAuthenticator();
		const theirs = stranger.create(options as never, at) as {
			id: string;
			response: { publicKey?: string };
		};
		const strangerKey: Credential = {
			...key,
			id: theirs.id,
			publicKey: theirs.response.publicKey ?? "",
		};
		const byStranger = JSON.stringify(
			stranger.get(
				cer.request(sha256(challengeInput(t, "get")), [strangerKey], "required") as never,
				at,
				{},
			),
		);
		const refusedFinish = await w.post(overHttp.operations.loginFinish.path, {
			statement: t,
			assertion: byStranger,
		});
		expect(refusedFinish.status).not.toBe(200);
		expect(w.opened).toEqual([]);
		expect(w.codesMade).toEqual([]);
		// ⑤⑥ The login's finish, by that key over T: the session and the code are the new subject's.
		const finished = await w.post(overHttp.operations.loginFinish.path, {
			statement: t,
			assertion: asserting(t),
		});
		expect(finished.status).toBe(200);
		const completion = await s.open(
			{
				enc: Buffer.from((finished.json.sealed as { enc: string }).enc, "base64url"),
				ct: Buffer.from((finished.json.sealed as { ct: string }).ct, "base64url"),
			},
			hpke.info.completion,
			new TextEncoder().encode(hpke.completionAad("authorization", tHash)),
		);
		expect(completion.kind).toBe("opened");
		expect(w.opened).toEqual([{ subject: "s-1" }]);
		expect(w.codesMade).toEqual([
			{
				subject: "s-1",
				clientId: "c1",
				session: "session-1",
				binding: { member: "jkt", confirmation: "jkt", tokenType: "DPoP" },
			},
		]);
		// The code rooted in T's approval, as a family would rest on it.
		expect(w.rooted).toEqual([{ code: "code-1", statement: tHash }]);
		// On the new subject's flow: its first key's change, then the approval by that key.
		const flow = w.book.sent
			.filter((sent) => sent.stage.flow.id === "s-1")
			.map((sent) => sent.stage.kind);
		expect(flow).toEqual(["keyChange", "approval"]);
		await w.app.stop();
	});
});

describe("a T the way back carries", () => {
	it("is made up to its route's bound and crosses the wire to the finish and the sign-up's continue; one longer is refused before T", async () => {
		const w = await f1World();
		await w.app.start();
		const s = await screen();
		const start = (jti: string, state: string) =>
			w.post(overHttp.operations.loginStart.path, {
				clientId: "c1",
				request: jarOf(w.now(), { jti, state }),
				eEnc: s.eEnc,
				eSigX: s.eSigX,
				eSigY: s.eSigY,
			});
		const finish = requests.loginFinish.fields.find((f) => f.name === "statement");
		const signUp = requests.continue.fields.find((f) => f.name === "statement");
		if (!finish || !signUp) throw new Error("no statement field");
		const bound = Math.min(finish.max, signUp.max);
		// The room left by a T of a short state, in its payload's bytes, each adds 4/3 of a character.
		const small = (await start("j0", "st")).json.statement as string;
		const payload = Buffer.from(small.split(".")[1] ?? "", "base64url").length;
		const room =
			Math.floor(((Math.ceil((payload * 4) / 3) + bound - small.length) * 3) / 4) - payload;
		const fits = await start("j1", `st${"a".repeat(room)}`);
		expect(fits).toMatchObject({ status: 200, json: { create: true } });
		const t = fits.json.statement as string;
		expect(t.length).toBeLessThanOrEqual(bound);
		expect(t.length).toBeGreaterThan(bound - 4);
		const bytes = new TextEncoder().encode(t);
		expect(checkField(finish, bytes)).toBeUndefined();
		expect(checkField(signUp, bytes)).toBeUndefined();
		// A few bytes more: refused before T, as the request object's, and nothing shown.
		expect(await start("j2", `st${"a".repeat(room + 3)}`)).toMatchObject({
			status: 400,
			json: { error: "invalid_request_object" },
		});
	});
});
