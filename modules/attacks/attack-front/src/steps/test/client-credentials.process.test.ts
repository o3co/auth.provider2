import { refusals, replies, requests } from "@mod/front-core-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signedMachine } from "../../../test/core/clients.ts";
import { readyWithinMs } from "../../../test/core/launch.ts";
import { type MachineClient, machineClient } from "../../../test/roles/machine.ts";
import { claimsOf, dpopKey } from "../../../test/roles/rp.ts";
import { provider, type World, world } from "./world.ts";

// The compromised Front's steps on a client's own token (client_credentials, the design note's §2):
// the Front holds no client key; it may replay, reroute or re-prove what a client sent through it.

const api = "https://api.example";
const notTaken = {
	error: "invalid_request",
	error_description: "authorization_details are not taken",
};
const keyNotTheClients = "the proof's key is not the key the client's assertion was verified with";
let w: World;
let mine: MachineClient;
let other: MachineClient;
beforeAll(async () => {
	mine = machineClient("svc-a", provider);
	// A client of the attacker's own, registered as honestly as any.
	other = machineClient("svc-b", provider);
	w = await world([], {
		signedClients: [
			await signedMachine(mine.id, mine.publicKey, [{ audience: api, scopes: ["read", "write"] }]),
			await signedMachine(other.id, other.publicKey, [{ audience: api, scopes: ["read"] }]),
		],
	});
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

/** The nonce the AS asks for, through `front`, by one request of the client's. */
async function nonceFor(front: Awaited<ReturnType<World["front"]>>, client: MachineClient) {
	const asked = await front.post(client.request("read", api));
	expect(asked.body).toMatchObject({ error: "use_dpop_nonce" });
	return asked.dpopNonce;
}

describe("the compromised Front on a client's own token", () => {
	it("issues the client its token through an honest Front, bound to its key, within its ceiling", async () => {
		const front = await w.front();
		const nonce = await nonceFor(front, mine);
		const answered = await front.post(mine.request("read", api, nonce));
		expect(answered.status, JSON.stringify(answered.body)).toBe(200);
		const token = (answered.body as { access_token: string }).access_token;
		expect(claimsOf(token)).toMatchObject({
			sub: mine.id,
			aud: api,
			scope: "read",
			cnf: { jkt: mine.jkt },
		});
	});

	it("F-10: a request sent again, an assertion for another AS, a proof by the Front's key or by another client's are refused by the Core", async () => {
		const front = await w.front();
		const nonce = await nonceFor(front, mine);
		// The frame the Front saw, sent again as it is: its assertion is spent. (Its first sending, taken,
		// is the control of this refusal and the next: the Core tells the client nothing more than this.)
		const frame = front.seen().at(-1);
		if (frame?.kind !== "clientCredentials") throw new Error("no client credentials seen");
		const again = await front.send("clientCredentials", frame.message as never);
		expect(again.outcome === "refused" && refusals[again.message.error - 1]).toBe("invalid_client");
		// The same request with a fresh proof of the client's (a control the Front could not make): the
		// spent assertion alone is refused.
		const fresh = await front.post({
			path: "/oauth/token",
			body: {
				grant_type: "client_credentials",
				scope: "read",
				resource: api,
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				client_assertion: (frame.message as { clientAssertion: string }).clientAssertion,
			},
			headers: { dpop: mine.proof(nonce) },
		});
		expect(fresh).toMatchObject({ status: 401, body: { error: "invalid_client" } });
		// The client's assertion for another AS (it uses its key there too): not this issuer's.
		const elsewhere = mine.request("read", api, nonce);
		const rerouted = await front.post({
			...elsewhere,
			body: { ...elsewhere.body, client_assertion: mine.assertion("https://other-as.example") },
		});
		expect(rerouted).toMatchObject({ status: 401, body: { error: "invalid_client" } });
		// The client's request, its proof swapped for one by the Front's own key (CC_ANY_DPOP_KEY).
		const thief = dpopKey();
		front.rewrite({
			messages: {
				clientCredentials: (message) => ({
					...message,
					dpop: thief.proof("POST", provider.tokenUrl, nonce),
				}),
			},
		});
		const swapped = await front.post(mine.request("read", api, nonce));
		expect(swapped.wire?.outcome).toBe("refused");
		expect(swapped.body).toEqual({
			error: "invalid_dpop_proof",
			error_description: keyNotTheClients,
		});
		// ... or by the key of another client the Front registered (CC_PROOF_ANY_REGISTERED).
		front.rewrite({
			messages: { clientCredentials: (message) => ({ ...message, dpop: other.proof(nonce) }) },
		});
		const registered = await front.post(mine.request("read", api, nonce));
		expect(registered.wire?.outcome).toBe("refused");
		expect(registered.body).toEqual({
			error: "invalid_dpop_proof",
			error_description: keyNotTheClients,
		});
		// The same rewrite with the client's own proof: issued, so the proof's key alone was refused.
		front.rewrite({
			messages: { clientCredentials: (message) => ({ ...message, dpop: mine.proof(nonce) }) },
		});
		expect((await front.post(mine.request("read", api, nonce))).status).toBe(200);
	});

	it("F-11 (structurally): the Core cannot ask the Front for a key set; every reply is an answer to a request", () => {
		// The wire's replies are ok, refused and rejected alone: no kind the Core sends unasked, so no
		// key set it fetches crosses a Front; the operations carry none either.
		expect(Object.keys(replies).sort()).toEqual(["ok", "refused", "rejected"]);
		const names = Object.values(requests).flatMap((kind) =>
			kind.fields.map((field) => field.name.toLowerCase()),
		);
		expect(
			names.filter(
				(name) => /jwk|keys|uri$/.test(name) && name !== "requesturi" && name !== "redirecturi",
			),
		).toEqual([]);
	});

	// F-11's other half, a client whose keys are at a key set's URL, needs a Core of its own beside a
	// key set the harness serves: jwks-uri.process.test.ts.

	it("F-12 (outside the claims): the scope rewritten in the body, within the client's ceiling, is what is issued", async () => {
		const front = await w.front();
		const nonce = await nonceFor(front, mine);
		front.rewrite({
			messages: { clientCredentials: (message) => ({ ...message, scope: "read write" }) },
		});
		const answered = await front.post(mine.request("read", api, nonce));
		expect(answered.status).toBe(200);
		// The Front widened the scope the client asked: the token says so; no claim covers it (witness).
		expect(claimsOf((answered.body as { access_token: string }).access_token)).toMatchObject({
			scope: "read write",
			cnf: { jkt: mine.jkt },
		});
		// Past the client's ceiling, the same rewrite is refused: the witness ends at the ceiling.
		const theirs = await w.front();
		const theirNonce = await nonceFor(theirs, other);
		theirs.rewrite({
			messages: { clientCredentials: (message) => ({ ...message, scope: "read write" }) },
		});
		expect((await theirs.post(other.request("read", api, theirNonce))).body).toMatchObject({
			error: "invalid_scope",
		});
	});

	it("A25: the client's request given authorization_details by the Front is refused by the Core, as on every grant", async () => {
		const front = await w.front();
		const nonce = await nonceFor(front, mine);
		front.rewrite({
			messages: { clientCredentials: (message) => ({ ...message, authorizationDetails: 1 }) },
		});
		const answered = await front.post(mine.request("read", api, nonce));
		expect(answered.wire?.outcome).toBe("refused");
		expect(answered.body).toEqual(notTaken);
		// Refused before the grant ran: the client's next request, without it, is issued.
		front.rewrite({});
		expect((await front.post(mine.request("read", api, nonce))).status).toBe(200);
	});
});
