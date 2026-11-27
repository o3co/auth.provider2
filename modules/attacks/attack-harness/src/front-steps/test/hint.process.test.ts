import { refusals } from "@mod/front-core-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { claimsOf } from "../../roles/test/rp.ts";
import { type Stopped, stopped } from "../../roles/test/screen.ts";
import { type World, world } from "./world.ts";

// An id_token_hint (OIDC Core §3.1.2.1, §3.1.2.2), a real ID token given back, through the Core as composed.

let w: World;
beforeAll(async () => {
	w = await world(["rp-hint"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as (typeof w.rps)[number];

/** A person's ID token from a login of their own, as the RP holds it. */
async function idTokenOf(person: Awaited<ReturnType<World["person"]>>) {
	const front = await w.front();
	const { session, s } = await w.started(person, rp(), front);
	const approved = await person.screen.approve(front, s, [person.credential]);
	if (stopped(approved)) throw new Error(JSON.stringify(approved));
	const asked = await front.post(rp().token(session, approved.code));
	const answered = await front.post(rp().token(session, approved.code, asked.dpopNonce));
	return (answered.body as { id_token: string }).id_token;
}

/** The word of the error a stop at the Core answered, as the wire numbers it. */
const coreError = (s: Stopped) =>
	s.stopped === "core" && s.answered.wire?.outcome === "refused"
		? refusals[s.answered.wire.message.error - 1]
		: undefined;

describe("an id_token_hint through the Core as composed", () => {
	it("starts and finishes for the subject the hint names, the hint verified by the authority's ring", async () => {
		const alice = await w.person();
		const hint = await idTokenOf(alice);
		const front = await w.front();
		const { s } = await w.started(alice, rp(), front, { id_token_hint: hint });
		const approved = await alice.screen.approve(front, s, [alice.credential]);
		expect(stopped(approved)).toBe(false);
	});

	it("finishes no login of another person under the hint: login_required, no code", async () => {
		const alice = await w.person();
		const bob = await w.person();
		const hint = await idTokenOf(alice);
		const front = await w.front();
		const { s } = await w.started(bob, rp(), front, { id_token_hint: hint });
		const approved = await bob.screen.approve(front, s, [bob.credential]);
		if (!stopped(approved)) throw new Error("a login of another subject was finished");
		expect(coreError(approved)).toBe("login_required");
	});

	it("starts no login whose hint's payload was changed under its signature: the ring refuses it (invalid_request)", async () => {
		const alice = await w.person();
		const bob = await w.person();
		const hint = await idTokenOf(alice);
		const [head, , signature] = hint.split(".");
		const claims = { ...claimsOf(hint), sub: claimsOf(await idTokenOf(bob)).sub };
		const forged = `${head}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${signature}`;
		const front = await w.front();
		const session = rp().authorization({ id_token_hint: forged });
		const s = await bob.screen.start(front, rp().clientId, session.jar);
		if (!stopped(s)) throw new Error("a start with a forged hint was answered");
		expect(coreError(s)).toBe("invalid_request");
	});
});
