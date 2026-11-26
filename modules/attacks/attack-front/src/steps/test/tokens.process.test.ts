import type { Message, WireReply } from "@mod/front-core-codec";
import { refusals } from "@mod/front-core-wire";
import { screenKeys } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../test/core/launch.ts";
import { dpopKey } from "../../../test/roles/rp.ts";
import { stopped } from "../../../test/roles/screen.ts";
import { provider, type World, world } from "./world.ts";

// The compromised Front's steps on PAR and the tokens (the design note's §2): the Front holds no
// client key, so it can only reuse what the RP sent through it, an assertion and a proof unspent
// where it kept the RP's request from the Core.

let w: World;
beforeAll(async () => {
	w = await world(["rp-tokens"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];
const thief = dpopKey();
const wordOf = (error: number) => refusals[error - 1];
/** The statement an `ok` reply of ② carries. */
const statementOf = (reply: WireReply) =>
	reply.outcome === "ok"
		? (JSON.parse(new TextDecoder().decode(reply.message.body)) as { statement: string }).statement
		: undefined;

describe("the compromised Front on PAR and the tokens", () => {
	it("F-2: a JAR pushed twice gives two request_uris, but a ② by the second under the Front's keys is refused (one reservation)", async () => {
		const victim = await w.person();
		const front = await w.front();
		const session = rp().authorization();
		const first = await front.post(rp().par(session.jar));
		// The PAR frame sent again: its assertion is spent, so the Core refuses it.
		const frame = front.seen().at(-1);
		if (frame?.kind !== "par") throw new Error("no PAR seen");
		const replayed = await front.send("par", frame.message as never);
		expect(replayed.outcome === "refused" && wordOf(replayed.message.error)).toBe("invalid_client");
		// The RP pushes the same JAR again (its first answer lost): PAR converges, it does not refuse.
		const second = await front.post(rp().par(session.jar));
		expect([first.status, second.status]).toEqual([201, 201]);
		const [one, two] = [first, second].map((p) => (p.body as { request_uri: string }).request_uri);
		expect([typeof one, typeof two]).toEqual(["string", "string"]);
		expect(one).not.toBe(two);
		const s = await victim.screen.start(front, rp().clientId, session.jar, one);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		// The victim's ② sent again by the second request_uri, under the same screen keys: the same T.
		const victims = front.seen().findLast((r) => r.kind === "loginStart");
		if (victims?.kind !== "loginStart") throw new Error("no ② seen");
		const resent = await front.send("loginStart", {
			...(victims.message as Message<"loginStart">),
			requestUri: two ?? "",
		});
		expect(resent.outcome === "ok" && statementOf(resent)).toBe(s.t.compact);
		const own = await screenKeys();
		const theirs = await front.send("loginStart", {
			source: w.fresh(),
			clientId: rp().clientId,
			request: "",
			requestUri: two ?? "",
			eEnc: Buffer.from(own.eEnc, "base64url"),
			eSigX: Buffer.from(own.eSig.x, "base64url"),
			eSigY: Buffer.from(own.eSig.y, "base64url"),
		});
		expect(theirs.outcome === "refused" && wordOf(theirs.message.error)).toBe("invalid_request");
	});

	it("F-3: the RP's PAR given a DPoP header of the Front's key is refused: a pushed binding comes from the signed JAR alone (A44)", async () => {
		const front = await w.front();
		// A nonce, as the AS gives it: the Front puts its own proof on one PAR of the RP's and is asked for one.
		const asked = await front.post({
			...rp().par(rp().authorization().jar),
			headers: { dpop: thief.proof("POST", provider.parUrl) },
		});
		expect(asked.body).toMatchObject({ error: "use_dpop_nonce" });
		front.rewrite({
			messages: {
				par: (message) => ({
					...message,
					dpop: thief.proof("POST", provider.parUrl, asked.dpopNonce),
				}),
			},
		});
		const pushed = await front.post(rp().par(rp().authorization().jar));
		expect(pushed.wire?.outcome).toBe("refused");
		expect(pushed.body).toEqual({
			error: "invalid_dpop_proof",
			error_description: "the proof is not of the key the request names",
		});
		// The same rewrite with the key the JAR names: pushed, so the Front's key alone was refused.
		const session = rp().authorization();
		front.rewrite({
			messages: {
				par: (message) => ({
					...message,
					dpop: session.proof("POST", provider.parUrl, asked.dpopNonce),
				}),
			},
		});
		expect((await front.post(rp().par(session.jar))).status).toBe(201);
	});

	it("F-14: a refresh under the Front's DPoP key is refused (the family's dpop_jkt); the code sent again ends the family", async () => {
		const victim = await w.person();
		const front = await w.front();
		const { session, s } = await w.started(victim, rp(), front);
		const approved = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(approved)) throw new Error(JSON.stringify(approved));
		const asked = await front.post(rp().token(session, approved.code));
		const tokens = await front.post(rp().token(session, approved.code, asked.dpopNonce));
		const { refresh_token } = tokens.body as { refresh_token: string };
		// The RP's refresh, its proof swapped for the Front's: the family is bound to the RP's key.
		front.rewrite({
			messages: {
				refresh: (message) => ({
					...message,
					dpop: thief.proof("POST", provider.tokenUrl, asked.dpopNonce),
				}),
			},
		});
		const stolen = await front.post(rp().refresh(session, refresh_token, asked.dpopNonce));
		expect(stolen.wire?.outcome).toBe("refused");
		expect(stolen.body).toEqual({
			error: "invalid_grant",
			error_description: "invalid refresh token",
		});
		// The RP's own refresh after it is taken: so the Front's key alone was refused, the family alive.
		front.rewrite({});
		const own = await front.post(rp().refresh(session, refresh_token, asked.dpopNonce));
		expect(own.status, JSON.stringify(own.body)).toBe(200);
		// The RP's next refresh, kept from the Core: its assertion and proof, unspent, carry the old code.
		const kept = rp().refresh(session, refresh_token, asked.dpopNonce);
		const resent = await front.post({
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: approved.code,
				redirect_uri: rp().redirectUri,
				code_verifier: session.verifier,
				client_assertion_type: kept.body.client_assertion_type ?? "",
				client_assertion: kept.body.client_assertion ?? "",
			},
			headers: kept.headers ?? {},
		});
		expect(resent.body).toMatchObject({ error: "invalid_grant" });
		// The family is ended: the RP's own refresh after it is refused too.
		const after = await front.post(rp().refresh(session, refresh_token, asked.dpopNonce));
		expect(after.body).toMatchObject({ error: "invalid_grant" });
	});
});
