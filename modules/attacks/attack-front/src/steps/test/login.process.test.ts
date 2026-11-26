import type { Message, WireReply } from "@mod/front-core-codec";
import { refusals } from "@mod/front-core-wire";
import { challengeOf, screenKeys } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../test/core/launch.ts";
import { claimsOf, dpopKey } from "../../../test/roles/rp.ts";
import { stopped } from "../../../test/roles/screen.ts";
import { provider, type World, world } from "./world.ts";

// The compromised Front's steps on the login (the design note's §2): each its own subject, client
// session and source; each refused where the note says it is, by the Core, the SDK or the RP.

let w: World;
beforeAll(async () => {
	w = await world(["rp-login"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const utf8 = new TextEncoder();
const text = new TextDecoder();
const rp = () => w.rps[0] as (typeof w.rps)[number];

/** The statement an `ok` reply of ② carries. */
const statementOf = (reply: WireReply) =>
	reply.outcome === "ok"
		? (JSON.parse(text.decode(reply.message.body)) as { statement: string }).statement
		: undefined;

/** A reply `ok` whose JSON body is changed by `change`. */
const withBody = (
	reply: WireReply,
	change: (body: Record<string, unknown>) => Record<string, unknown>,
): WireReply =>
	reply.outcome === "ok"
		? {
				...reply,
				message: {
					...reply.message,
					body: utf8.encode(JSON.stringify(change(JSON.parse(text.decode(reply.message.body))))),
				},
			}
		: reply;

describe("the compromised Front on a login", () => {
	it("F-1: a second ② of the victim's JAR under the Front's keys is refused (A20), and a code swapped into the RP's exchange is refused, its ID token failing the RP's c_hash (R15)", async () => {
		const victim = await w.person();
		const front = await w.front();
		const { session, s } = await w.started(victim, rp(), front);
		const first = front.seen().find((r) => r.kind === "loginStart");
		if (first?.kind !== "loginStart") throw new Error("no ② seen");
		const victims = first.message as Message<"loginStart">;
		// The same ② again, the same screen keys: the same T (the reservation converges).
		const same = await front.send("loginStart", victims);
		expect(same.outcome === "ok" && statementOf(same)).toBe(s.t.compact);
		// Under the Front's own screen keys: refused, so no T of the victim's JAR is sealed to the Front.
		const own = await screenKeys();
		const again = await front.send("loginStart", {
			...victims,
			eEnc: Buffer.from(own.eEnc, "base64url"),
			eSigX: Buffer.from(own.eSig.x, "base64url"),
			eSigY: Buffer.from(own.eSig.y, "base64url"),
		});
		expect(again.outcome === "refused" && refusals[again.message.error - 1]).toBe(
			"invalid_request",
		);
		// Hole A's second half: the RP's exchange given another authorization's code (the attacker's own login).
		const victimCode = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(victimCode)) throw new Error(JSON.stringify(victimCode));
		const attacker = await w.person();
		const login = async () => {
			const started = await w.started(attacker, rp(), front);
			const called = await attacker.screen.approve(front, started.s, [attacker.credential]);
			if (stopped(called)) throw new Error(JSON.stringify(called));
			return { session: started.session, code: called.code };
		};
		const theirCode = await login();
		const asked = await front.post(rp().token(session, victimCode.code));
		front.rewrite({ messages: { token: (message) => ({ ...message, code: theirCode.code }) } });
		const swapped = await front.post(rp().token(session, victimCode.code, asked.dpopNonce));
		expect(swapped.wire?.outcome).toBe("refused");
		expect(swapped.body).toMatchObject({ error: "invalid_grant" });
		// Were an ID token for another code handed back (the attacker's own, from a login it redeems; the
		// swapped code is spent by the refusal), the RP's c_hash over the code it sent refuses it.
		front.rewrite({});
		const theirs = await login();
		const theirAsked = await front.post(rp().token(theirs.session, theirs.code));
		const theirTokens = await front.post(
			rp().token(theirs.session, theirs.code, theirAsked.dpopNonce),
		);
		const { id_token } = theirTokens.body as { id_token: string };
		expect(rp().idTokenFaults(id_token, theirs.session, theirs.code, w.core.jwks)).toEqual([]);
		expect(rp().idTokenFaults(id_token, session, victimCode.code, w.core.jwks)).toContain("c_hash");
	});

	it("F-4: the Front sees no code before the RP's token request, in any byte it relays or in any JWS it could read", async () => {
		const victim = await w.person();
		const front = await w.front();
		const { s } = await w.started(victim, rp(), front);
		const approved = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(approved)) throw new Error(JSON.stringify(approved));
		// Every value of every frame and reply, whole: text, bytes read as UTF-8 and as latin1, and each
		// base64url segment of a value decoded (a JWS's header and payload among them).
		const seen: string[] = [];
		const collect = (value: unknown): void => {
			if (value instanceof Uint8Array) {
				seen.push(text.decode(value), Buffer.from(value).toString("latin1"));
				collect(text.decode(value));
			} else if (typeof value === "string") {
				seen.push(value);
				for (const part of value.split(/[^A-Za-z0-9_-]+/))
					if (part.length >= 4) seen.push(Buffer.from(part, "base64url").toString("latin1"));
			} else if (value !== null && typeof value === "object") Object.values(value).forEach(collect);
			else if (value !== undefined) seen.push(String(value));
		};
		for (const relayed of front.seen()) collect([relayed.message, relayed.reply]);
		// The login's finish answers the sealed completion alone.
		const finish = front.seen().find((r) => r.kind === "loginFinish")?.reply;
		expect(
			finish?.outcome === "ok" && Object.keys(JSON.parse(text.decode(finish.message.body))),
		).toEqual(["sealed"]);
		expect(seen.length).toBeGreaterThan(0);
		expect(seen.filter((value) => value.includes(approved.code))).toEqual([]);
	});

	it("F-5: T swapped for one naming the Front's screen keys is refused by the SDK's authorization.read", async () => {
		const victim = await w.person();
		const attacker = await w.person();
		const front = await w.front();
		const theirs = await w.started(attacker, rp(), front);
		front.rewrite({
			replies: {
				loginStart: (reply) =>
					withBody(reply, (body) => ({ ...body, statement: theirs.s.t.compact })),
			},
		});
		const s = await victim.screen.start(front, rp().clientId, rp().authorization().jar);
		expect(s).toMatchObject({ stopped: "sdk", at: "authorization.read", error: "keys" });
	});

	it("F-6: the attacker's own passkey's assertion over the victim's T: the SDK's finish refuses the completion", async () => {
		const victim = await w.person();
		const attacker = await w.person();
		const front = await w.front();
		const { s } = await w.started(victim, rp(), front);
		const theirs = attacker.browser.get({
			challenge: await challengeOf(s.t.compact, "get"),
			rpId: new URL(attacker.browser.origin).hostname,
			allowCredentials: [{ type: "public-key", id: Buffer.from(attacker.credential, "base64url") }],
			userVerification: "required",
		});
		front.rewrite({ messages: { loginFinish: (message) => ({ ...message, assertion: theirs }) } });
		const approved = await victim.screen.approve(front, s, [victim.credential]);
		expect(approved).toMatchObject({
			stopped: "sdk",
			at: "authorization.finish",
			error: "assertion",
		});
		// The Core took the attacker's assertion as the attacker's approval: its reply was a completion.
		expect(front.seen().findLast((r) => r.kind === "loginFinish")?.reply.outcome).toBe("ok");
	});

	it("F-7: the victim's tokens handed to another session of the RP fail its nonce check (R2)", async () => {
		const victim = await w.person();
		const front = await w.front();
		const { session, s } = await w.started(victim, rp(), front);
		const other = rp().authorization();
		const approved = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(approved)) throw new Error(JSON.stringify(approved));
		const asked = await front.post(rp().token(session, approved.code));
		const answered = await front.post(rp().token(session, approved.code, asked.dpopNonce));
		const { id_token } = answered.body as { id_token: string };
		expect(rp().idTokenFaults(id_token, session, approved.code, w.core.jwks)).toEqual([]);
		// Handed to the other session (as the Front would answer its token request): its nonce alone fails.
		expect(rp().idTokenFaults(id_token, other, approved.code, w.core.jwks)).toEqual(["nonce"]);
	});

	it("F-8: another session's JAR given to the screen before it holds one: the RP's state check fails (R3)", async () => {
		const victim = await w.person();
		const front = await w.front();
		const mine = rp().authorization();
		const theirs = rp().authorization();
		// ① The Front delivers the other session's JAR to the victim's screen, which holds it as its own.
		const s = await victim.screen.start(front, rp().clientId, theirs.jar);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		const callback = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(callback)) throw new Error(JSON.stringify(callback));
		expect(rp().callbackFaults(callback, mine)).toEqual(["state"]);
		expect(rp().callbackFaults(callback, theirs)).toEqual([]);
	});

	it("F-13: the RP's code exchange sent under the Front's own DPoP key is refused by the Core (T's dpop_jkt), the code spent", async () => {
		/** A login's code, the RP's session and the nonce the AS asked, through `front`. */
		const coded = async (front: Awaited<ReturnType<World["front"]>>) => {
			const victim = await w.person();
			const { session, s } = await w.started(victim, rp(), front);
			const approved = await victim.screen.approve(front, s, [victim.credential]);
			if (stopped(approved)) throw new Error(JSON.stringify(approved));
			const asked = await front.post(rp().token(session, approved.code));
			return { code: approved.code, session, nonce: asked.dpopNonce };
		};
		const thief = dpopKey();
		const front = await w.front();
		const stolen = await coded(front);
		front.rewrite({
			messages: {
				token: (message) => ({
					...message,
					dpop: thief.proof("POST", provider.tokenUrl, stolen.nonce),
				}),
			},
		});
		const answered = await front.post(rp().token(stolen.session, stolen.code, stolen.nonce));
		expect(answered).toMatchObject({ status: 400, body: { error: "invalid_grant" } });
		expect(answered.wire?.outcome).toBe("refused");
		// The refused code is spent: the RP's own exchange after it is refused too (the Front could drop it anyway).
		front.rewrite({});
		const late = await front.post(rp().token(stolen.session, stolen.code, stolen.nonce));
		expect(late).toMatchObject({ status: 400, body: { error: "invalid_grant" } });
		// The same rewrite with the RP's own key: the exchange is taken, so the key alone was refused.
		const other = await w.front();
		const kept = await coded(other);
		other.rewrite({
			messages: {
				token: (message) => ({
					...message,
					dpop: kept.session.proof("POST", provider.tokenUrl, kept.nonce),
				}),
			},
		});
		const taken = await other.post(rp().token(kept.session, kept.code, kept.nonce));
		expect(taken.status, JSON.stringify(taken.body)).toBe(200);
		expect(claimsOf((taken.body as { access_token: string }).access_token)).toMatchObject({
			cnf: { jkt: kept.session.dpopJkt },
		});
	});
});
