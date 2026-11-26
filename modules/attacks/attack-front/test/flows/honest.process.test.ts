import { wireClient } from "@mod/core-wire/testing";
import { wireCertificates } from "@mod/front-relay/testing";
import { afterAll, beforeAll, expect, it } from "vitest";
import { badFront } from "../../src/contract.ts";
import { registered } from "../core/clients.ts";
import { readyWithinMs, type StartedCore, startCore } from "../core/launch.ts";
import { browser } from "../roles/browser.ts";
import { claimsOf, type RelyingParty, relyingParty } from "../roles/rp.ts";
import { loginScreen, stopped } from "../roles/screen.ts";

const origin = "https://issuer.example";
const screenOrigin = "https://login.example";
const provider = {
	issuer: origin,
	tokenUrl: `${origin}/oauth/token`,
	parUrl: `${origin}/oauth/par`,
};

let certificates: Awaited<ReturnType<typeof wireCertificates>>;
let core: StartedCore;
let rp: RelyingParty;
beforeAll(async () => {
	certificates = await wireCertificates();
	rp = relyingParty(provider, "rp-honest", "https://rp.example/cb");
	core = await startCore({
		certificates,
		origin,
		screen: screenOrigin,
		clients: [await registered(rp)],
	});
}, readyWithinMs + 10_000);
afterAll(async () => {
	await core?.stop();
	await certificates?.remove();
});

it("signs a person up (F1) and logs them in through an honest Front, the RP's checks all holding", async () => {
	const wire = await wireClient(core.port, certificates);
	try {
		const front = badFront(wire, "203.0.113.30");
		const screen = loginScreen({ ring: core.ring, issuer: origin }, browser(screenOrigin));
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
	} finally {
		wire.close();
	}
});
