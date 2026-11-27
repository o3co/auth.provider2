import { createHash } from "node:crypto";
import type { Message } from "@mod/front-core-codec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../pattern/test/launch.ts";
import { claimsOf, type Started as Session } from "../../../roles/test/rp.ts";
import { stopped } from "../../../roles/test/screen.ts";
import { type World, world } from "../../test/world.ts";

// A PAR login through the real SDK (§3.3): the RP pushes its JAR, the screen is reached by client_id
// and request_uri alone and holds no JAR, and reads T by readPushed. Beside it, the compromised Front's
// swaps of the request, inside ② (the screen refuses) and at the URL (the RP's R3 refuses).

let w: World;
beforeAll(async () => {
	w = await world(["rp-par"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];
const text = new TextDecoder();
const hashOf = (jar: string) => createHash("sha256").update(jar).digest("base64url");

/** A session of the RP's, its JAR pushed through `front`: the session and the request_uri PAR answered. */
async function pushed(front: Awaited<ReturnType<World["front"]>>): Promise<[Session, string]> {
	const session = rp().authorization();
	const answered = await front.post(rp().par(session.jar));
	expect(answered.status).toBe(201);
	return [session, (answered.body as { request_uri: string }).request_uri];
}

/** Whether any byte the Front relayed, as text or decoded from base64url, holds `code`. */
function frontSaw(front: Awaited<ReturnType<World["front"]>>, code: string): boolean {
	const seen: string[] = [];
	const collect = (value: unknown): void => {
		if (value instanceof Uint8Array) collect(text.decode(value));
		else if (typeof value === "string") {
			seen.push(value);
			for (const part of value.split(/[^A-Za-z0-9_-]+/))
				if (part.length >= 4) seen.push(Buffer.from(part, "base64url").toString("latin1"));
		} else if (value !== null && typeof value === "object") Object.values(value).forEach(collect);
	};
	for (const relayed of front.seen()) collect([relayed.message, relayed.reply]);
	return seen.some((value) => value.includes(code));
}

describe("a PAR login through the real SDK", () => {
	it("logs in by the request_uri alone, T the RP's pushed request, the code redeemed and the ID token checked", async () => {
		const victim = await w.person();
		const front = await w.front();
		const [session, uri] = await pushed(front);
		const s = await victim.screen.startPushed(front, rp().clientId, uri);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		// The RP's side: T is for the JAR it pushed, of its session, under the request_uri PAR gave.
		expect(s.t.statement.approval).toMatchObject({
			jar_hash: hashOf(session.jar),
			state: session.state,
			nonce: session.nonce,
			dpop_jkt: session.dpopJkt,
			request_uri: uri,
		});
		const callback = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(callback)) throw new Error(JSON.stringify(callback));
		expect(rp().callbackFaults(callback, session)).toEqual([]);
		const asked = await front.post(rp().token(session, callback.code));
		const answered = await front.post(rp().token(session, callback.code, asked.dpopNonce));
		expect(answered.status).toBe(200);
		const { id_token } = answered.body as { id_token: string };
		expect(rp().idTokenFaults(id_token, session, callback.code, w.core.jwks)).toEqual([]);
	});

	it("refuses at the screen another request of the same client the Front puts inside ②, in either form", async () => {
		const victim = await w.person();
		const front = await w.front();
		const [, mine] = await pushed(front);
		const [, theirs] = await pushed(front);
		front.rewrite({
			messages: { loginStart: (m: Message<"loginStart">) => ({ ...m, requestUri: theirs }) },
		});
		expect(await victim.screen.startPushed(front, rp().clientId, mine)).toMatchObject({
			stopped: "sdk",
			at: "authorization.readPushed",
			error: "request_uri",
		});
		// Rewritten into the other form: another session's JAR by value, which names no request_uri.
		const other = rp().authorization();
		const byValue = await w.front();
		byValue.rewrite({
			messages: {
				loginStart: (m: Message<"loginStart">) => ({ ...m, requestUri: "", request: other.jar }),
			},
		});
		expect(await victim.screen.startPushed(byValue, rp().clientId, mine)).toMatchObject({
			stopped: "sdk",
			at: "authorization.readPushed",
			error: "request_uri",
		});
	});

	it("refuses by value, as the contrast, another JAR the Front puts inside ②: its items", async () => {
		const victim = await w.person();
		const front = await w.front();
		const mine = rp().authorization();
		const theirs = rp().authorization();
		front.rewrite({
			messages: { loginStart: (m: Message<"loginStart">) => ({ ...m, request: theirs.jar }) },
		});
		expect(await victim.screen.start(front, rp().clientId, mine.jar)).toMatchObject({
			stopped: "sdk",
			at: "authorization.read",
			error: "items",
		});
	});

	it("leaves to the RP's R3 another session's request_uri the Front gives the victim's screen at the URL", async () => {
		const victim = await w.person();
		const attacker = await w.person();
		const front = await w.front();
		const mine = rp().authorization();
		// The attacker's own session at the RP, its JAR pushed as any push.
		const [theirs, uri] = await pushed(front);
		// ① The Front hands the victim's screen the attacker session's request_uri: T is its own URL's.
		const s = await victim.screen.startPushed(front, rp().clientId, uri);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		const callback = await victim.screen.approve(front, s, [victim.credential]);
		if (stopped(callback)) throw new Error(JSON.stringify(callback));
		// R3: the victim's session refuses it at state; the attacker session's would take it.
		expect(rp().callbackFaults(callback, mine)).toEqual(["state"]);
		expect(rp().callbackFaults(callback, theirs)).toEqual([]);
		// The Front never saw the code: the completion is sealed to the victim screen's key.
		expect(frontSaw(front, callback.code)).toBe(false);
		// The attacker's own ② by that request_uri, under its own keys: the reservation is the victim's.
		expect(await attacker.screen.startPushed(front, rp().clientId, uri)).toMatchObject({
			stopped: "core",
			at: "/login/start",
			answered: {
				body: { error: "invalid_request", error_description: "the request was used already" },
			},
		});
		// The control: given the code, the Core redeems it under the attacker's session, so R3 is what
		// must refuse it, not the Core.
		const asked = await front.post(rp().token(theirs, callback.code));
		const answered = await front.post(rp().token(theirs, callback.code, asked.dpopNonce));
		expect(answered.status).toBe(200);
		const { id_token } = answered.body as { id_token: string };
		expect(rp().idTokenFaults(id_token, theirs, callback.code, w.core.jwks)).toEqual([]);
		// The scan's positive control: once the code crossed the Front in that token request, it sees it.
		expect(frontSaw(front, callback.code)).toBe(true);
		// And it names the victim: the subject the victim's own honest login gives.
		const [own, ownUri] = await pushed(front);
		const honest = await victim.screen.startPushed(front, rp().clientId, ownUri);
		if (stopped(honest)) throw new Error(JSON.stringify(honest));
		const back = await victim.screen.approve(front, honest, [victim.credential]);
		if (stopped(back)) throw new Error(JSON.stringify(back));
		const ownAsked = await front.post(rp().token(own, back.code));
		const ownAnswered = await front.post(rp().token(own, back.code, ownAsked.dpopNonce));
		const victimSub = claimsOf((ownAnswered.body as { id_token: string }).id_token).sub;
		expect(typeof victimSub).toBe("string");
		expect(claimsOf(id_token).sub).toBe(victimSub);
	});
});
