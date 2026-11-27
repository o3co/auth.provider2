import { afterAll, beforeAll, expect, it } from "vitest";
import { type Held, holdCertificates } from "../../pattern/test/certificates.ts";
import { readyWithinMs, type StartedCore, startCore } from "../../pattern/test/launch.ts";
import { honestRelay } from "../../relay/relay.ts";
import { browser } from "../../roles/test/browser.ts";
import { claimsOf, type RelyingParty } from "../../roles/test/rp.ts";
import { stopped } from "../../roles/test/screen.ts";
import { origin, relyingParties, screenOrigin, type World, world } from "./world.ts";

// The world on the harness's Core started in a process of its own, its Fronts honest.
let held: Held;
let core: StartedCore;
let rp: RelyingParty;
let w: World;
beforeAll(async () => {
	held = await holdCertificates();
	const { rps, clients } = await relyingParties(["rp-honest"]);
	rp = rps[0] as RelyingParty;
	core = await startCore({
		certificates: held.certificates,
		origin,
		screen: screenOrigin,
		clients,
	});
	w = world({ ...core, certificates: held.certificates }, rps, honestRelay);
}, readyWithinMs + 10_000);
afterAll(async () => {
	try {
		await w?.stop();
	} finally {
		await held?.letGo();
	}
});

it("signs a person up (F1) and logs them in through an honest Front, the RP's checks all holding", async () => {
	const front = await w.front();
	const screen = w.screenOf(browser(screenOrigin));
	const started = rp.authorization();
	const s = await screen.start(front, rp.clientId, started.jar);
	if (stopped(s)) throw new Error(`start: ${JSON.stringify(s)}`);
	expect(s.create).toBe(true);
	const key = await screen.signUp(front, s);
	if (stopped(key)) throw new Error(`sign-up: ${JSON.stringify(key)}`);
	const approved = await screen.approve(front, s, [key.credential]);
	if (stopped(approved)) throw new Error(`approve: ${JSON.stringify(approved)}`);
	// The page POSTs the code and T's state to the RP's redirect URI, not through the Front (R3).
	expect(rp.callbackFaults(approved, started)).toEqual([]);
	// The AS asks for a nonce first (RFC 9449 §8), and the proof carrying it is taken.
	const asked = await front.post(rp.token(started, approved.code));
	expect(asked).toMatchObject({ status: 400, body: { error: "use_dpop_nonce" } });
	expect(asked.dpopNonce).toBeTypeOf("string");
	const answered = await front.post(rp.token(started, approved.code, asked.dpopNonce));
	expect(answered.status, JSON.stringify(answered.body)).toBe(200);
	const tokens = answered.body as { id_token: string; access_token: string; token_type: string };
	expect(tokens.token_type).toBe("DPoP");
	// The access token is bound to the RP's DPoP key, as T's dpop_jkt asked (claim 2's honest side).
	expect(claimsOf(tokens.access_token)).toMatchObject({ cnf: { jkt: started.dpopJkt } });
	expect(rp.idTokenFaults(tokens.id_token, started, approved.code, core.jwks)).toEqual([]);
	expect(claimsOf(tokens.id_token).sub).toBeTypeOf("string");
});

it("signs a person up through an honest Front of its own, their key the one the world gives", async () => {
	const who = await w.person();
	expect(who.credential).toBeTypeOf("string");
	const front = await w.front();
	const { session, s } = await w.started(who, rp, front);
	const approved = await who.screen.approve(front, s, [who.credential]);
	if (stopped(approved)) throw new Error(`approve: ${JSON.stringify(approved)}`);
	expect(rp.callbackFaults(approved, session)).toEqual([]);
});
