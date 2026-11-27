import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { browser } from "../../roles/test/browser.ts";
import { stopped } from "../../roles/test/screen.ts";
import { type World, world } from "./world.ts";

// The compromised Front's steps on F1's sign-up (F-18), and the claims parameter's bridge wired or not
// (F-21: not an attack, the wiring checked end to end on the Core the harness runs).

let w: World;
let bare: World;
beforeAll(async () => {
	[w, bare] = await Promise.all([
		world(["rp-claims"]),
		world(["rp-bare"], { change: ["-@mod/authorize-claims"] }),
	]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await Promise.all([w?.stop(), bare?.stop()]);
});

const rpOf = (of: World) => of.rps[0] as World["rps"][number];

describe("the compromised Front on a sign-up (F1)", () => {
	it("F-18: another T's creation handed to the screen for its sign-up is refused by the SDK's signUp.readCreation", async () => {
		const front = await w.front();
		// The Front's own sign-up, under another T, gives it a creation of its own.
		const theirs = w.screenOf((await w.person()).browser);
		const started = await theirs.start(front, rpOf(w).clientId, rpOf(w).authorization().jar);
		if (stopped(started)) throw new Error(JSON.stringify(started));
		await theirs.signUp(front, started);
		const creation = front
			.seen()
			.find((r) => r.kind === "continue" && r.reply.outcome === "ok")?.reply;
		if (creation?.outcome !== "ok") throw new Error("no creation seen");
		// The victim's sign-up answered with it.
		const victim = await w.front();
		const screen = w.screenOf(browser("https://login.example"));
		const s = await screen.start(victim, rpOf(w).clientId, rpOf(w).authorization().jar);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		victim.rewrite({ replies: { continue: () => creation } });
		const signedUp = await screen.signUp(victim, s);
		expect(signedUp).toMatchObject({ stopped: "sdk", at: "signUp.readCreation", error: "keys" });
	});
});

describe("the claims parameter's bridge (F-21)", () => {
	/** A login of a person at an RP, its JAR's items given: its ID token's faults as the RP checks them (none for one it takes), or where it stopped. */
	const login = async (of: World, items: Record<string, unknown> = {}) => {
		const person = await of.person(rpOf(of));
		const front = await of.front();
		const session = rpOf(of).authorization(items);
		const s = await person.screen.start(front, rpOf(of).clientId, session.jar);
		if (stopped(s)) return s;
		const approved = await person.screen.approve(front, s, [person.credential]);
		if (stopped(approved)) return approved;
		const asked = await front.post(rpOf(of).token(session, approved.code));
		const tokens = await front.post(rpOf(of).token(session, approved.code, asked.dpopNonce));
		if (tokens.status !== 200)
			return { stopped: "core" as const, at: "/oauth/token", answered: tokens };
		const idToken = (tokens.body as { id_token?: unknown }).id_token;
		if (typeof idToken !== "string") return { faults: ["no ID token"] };
		return { faults: rpOf(of).idTokenFaults(idToken, session, approved.code, of.core.jwks) };
	};

	it("composed: the discovery document says the parameter is supported, and a claims request is read end to end", async () => {
		expect(w.core.metadata.claims_parameter_supported).toBe(true);
		// A request asking an ID token's sub of another subject: read at the finish, refused there.
		const other = await login(w, { claims: { id_token: { sub: { value: "someone-else" } } } });
		expect(other).toMatchObject({
			stopped: "core",
			at: "/login/finish",
			answered: { body: { error_description: "the login is not of the subject asked" } },
		});
		// An essential acr the login does not meet: read at the finish too, an authentication that failed.
		const acr = await login(w, {
			claims: { id_token: { acr: { essential: true, values: ["urn:unmet"] } } },
		});
		expect(acr).toMatchObject({
			stopped: "core",
			at: "/login/finish",
			answered: { body: { error_description: "the login does not meet the acr asked" } },
		});
		// One the login meets goes through: the parameter only holds back. Its release of a claim asked by
		// name is not reached here (users-local holds no attributes, the acr table is empty): oidc's tests.
		expect(await login(w, { claims: { id_token: { email: { essential: true } } } })).toEqual({
			faults: [],
		});
	});

	it("composed: a claim asked in the null form (OpenID Connect Core §5.5's plain ask) is read end to end, the screen's SDK taking T and the RP the ID token", async () => {
		// The form RPs send most: a member asked with no constraint, written as null.
		expect(await login(w, { claims: { id_token: { email: null } } })).toEqual({ faults: [] });
		// Beside a constraint the finish holds it to: the null form is read as an ask, not dropped.
		const other = await login(w, {
			claims: { id_token: { email: null, sub: { value: "someone-else" } } },
		});
		expect(other).toMatchObject({
			stopped: "core",
			at: "/login/finish",
			answered: { body: { error_description: "the login is not of the subject asked" } },
		});
		// Any other null in the parameter is no form §5.5 gives: refused before T, never a server error.
		const stray = await login(w, { claims: { id_token: { email: { value: null } } } });
		expect(stray).toMatchObject({
			stopped: "core",
			at: "/login/start",
			answered: { status: 400, body: { error: "invalid_request_object" } },
		});
	});

	it("not composed: the document names no such parameter, and a claims request is refused before T", async () => {
		expect(bare.core.metadata).not.toHaveProperty("claims_parameter_supported");
		const asked = await login(bare, { claims: { id_token: { auth_time: { essential: true } } } });
		expect(asked).toMatchObject({ stopped: "core", at: "/login/start" });
		// Without the parameter, the same Core logs the person in.
		expect(await login(bare)).toEqual({ faults: [] });
	});
});
