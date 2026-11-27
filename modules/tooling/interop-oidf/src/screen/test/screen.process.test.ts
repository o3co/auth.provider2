import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Jwk } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dpopKey, type Provider, relyingParty, send } from "../../rp/test/rp.ts";
import { type Answered, type At, ask, atIssuer } from "../../scene/test/ask.ts";
import { heldUnderAudit } from "../../scene/test/held.ts";
import { type Scene, startScene } from "../../scene/test/scene.ts";
import { words } from "../../words/words.ts";
import { browser } from "./browser.ts";
import { type Carrying, type Pages, startPages } from "./page.ts";
import { type LoginScreen, loginScreen, type Pins, type Post, stopped } from "./screen.ts";

/** A redirect URI with a query of its own, as the suite registers one: the answer keeps it. */
const redirectUri = "https://rp.example.invalid/cb?dummy1=lorem&dummy2=ipsum";

let dir = "";
let scene: Scene | undefined;
let pages: Pages | undefined;
let role: LoginScreen | undefined;
let carrying: Carrying = "form_post";

const issuer = (): Scene => {
	if (scene === undefined) throw new Error("the scene did not start");
	return scene;
};
const provider = (): Provider => {
	const { issuer: at } = issuer();
	return { issuer: at, parUrl: `${at}/oauth/par`, tokenUrl: `${at}/oauth/token` };
};
const rp = relyingParty("rp-screen", redirectUri, provider);
const at = (path: string, init: Parameters<typeof ask>[2]) => ask(atIssuer(issuer()), path, init);
/** The Core's answer to the next finish, where a test makes it refuse (the JSON a refused start answers); the scene's otherwise. */
let finishAnswer: { readonly status: number; readonly body: unknown } | undefined;
const post: Post = async (path, body) => {
	if (path === "/login/finish" && finishAnswer !== undefined) return finishAnswer;
	const answer = await ask(atIssuer(issuer()), path, { method: "POST", json: body });
	return { status: answer.status, body: answer.json };
};

/** The pages, as the suite's browser reaches them. */
const atPages = (): At => {
	if (pages === undefined) throw new Error("the pages did not start");
	return { origin: pages.origin, certificate: pages.certificate };
};

const unescaped = (text: string) =>
	text.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));

/** A page's forms as a browser reads them: each one's id, method, action, hidden inputs and buttons. */
function formsOf(html: string) {
	return [...html.matchAll(/<form([^>]*)>(.*?)<\/form>/gs)].map((m) => {
		const attribute = (name: string) =>
			unescaped(new RegExp(`${name}="([^"]*)"`).exec(m[1] ?? "")?.[1] ?? "");
		const inner = m[2] ?? "";
		return {
			id: attribute("id"),
			method: attribute("method"),
			action: attribute("action"),
			hidden: Object.fromEntries(
				[...inner.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)].map((h) => [
					unescaped(h[1] ?? ""),
					unescaped(h[2] ?? ""),
				]),
			),
			buttons: [...inner.matchAll(/<button([^>]*)>/g)].map((b) => {
				const of = (name: string) => new RegExp(`${name}="([^"]*)"`).exec(b[1] ?? "")?.[1];
				return { id: of("id"), name: of("name"), value: of("value"), type: of("type") };
			}),
		};
	});
}

/** The suite's browser pressing the button of this id on the page: its form sent as the browser sends it. */
async function press(shown: Answered, buttonId: string): Promise<Answered> {
	const form = formsOf(shown.text).find((f) => f.buttons.some((b) => b.id === buttonId));
	if (form === undefined) throw new Error(`no button ${buttonId} on the page:\n${shown.text}`);
	const button = form.buttons.find((b) => b.id === buttonId);
	expect(form.method, "the form's method").toBe("post");
	expect(button?.type).toBe("submit");
	const pressed = button?.name === undefined ? {} : { [button.name]: button.value ?? "" };
	return ask(atPages(), form.action, { method: "POST", form: { ...form.hidden, ...pressed } });
}

/** The page the RP's answer is in, as a browser posts it on: its callback form, sent by itself or by Continue. */
function callbackOf(answered: Answered) {
	expect(answered.status, answered.text).toBe(200);
	const form = formsOf(answered.text).find((f) => f.id === "callback");
	if (form === undefined) throw new Error(`no callback form:\n${answered.text}`);
	expect(form.method).toBe("post");
	expect(form.buttons.map((b) => [b.id, b.type])).toEqual([["continue", "submit"]]);
	expect(answered.text).toContain('document.getElementById("callback").submit()');
	return form;
}

/** A JAR pushed: the RP's session and the request_uri the provider gave. */
async function pushed() {
	const session = rp.authorization();
	const { answer } = await send(at, "/oauth/par", () => rp.par(session));
	expect(answer.status, answer.text).toBe(201);
	return { session, requestUri: String(answer.json.request_uri) };
}

/** The suite's browser at the authorization page for this request_uri. */
async function shown(requestUri: string) {
	const query = new URLSearchParams({ client_id: rp.clientId, request_uri: requestUri });
	const page = await ask(atPages(), `/authorize?${query}`);
	expect(page.status, page.text).toBe(200);
	return page;
}

const lastSeen = () => pages?.seen().at(-1);

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "interop-oidf-screen-"));
	// The pages first: their origin is the screen's, which the Core's WebAuthn and authorize name.
	pages = await startPages({
		host: "localhost",
		listen: "127.0.0.1",
		dir,
		screen: () => {
			if (role === undefined) throw new Error("no screen");
			return role;
		},
		post: () => post,
		carrying: () => carrying,
	});
	scene = await startScene({
		host: "localhost",
		listen: "127.0.0.1",
		screen: pages.origin,
		clients: [rp.registered()],
	});
	const coreKeys = (await ask(atIssuer(scene), "/core-keys.json")).json.keys as readonly (Jwk & {
		readonly use?: string;
	})[];
	const pins: Pins = { ring: coreKeys.filter((key) => key.use !== "enc"), issuer: scene.issuer };
	role = loginScreen(() => pins, browser(pages.origin));
	// The person signs up once, under PAR: T offers the sign-up, the passkey made in the browser.
	const { requestUri } = await pushed();
	const started = await role.startPushed(post, rp.clientId, requestUri);
	if (stopped(started)) throw new Error(`the sign-up's start: ${JSON.stringify(started)}`);
	expect(started.create).toBe(true);
	const key = await role.signUp(post, started);
	if (stopped(key)) throw new Error(`the sign-up: ${JSON.stringify(key)}\n${scene.output()}`);
}, 180_000);

afterAll(async () => {
	await scene?.stop();
	await pages?.stop();
	if (dir !== "") await rm(dir, { recursive: true, force: true });
}, 30_000);

describe("the login screen, its pages before the scene", () => {
	it("logs the person in under PAR, the code by form_post to the RP, exchanged for tokens bound to the session's key", async () => {
		carrying = "form_post";
		const { session, requestUri } = await pushed();
		const callback = callbackOf(await press(await shown(requestUri), "approve"));
		expect(callback.action).toBe(redirectUri);
		expect(callback.hidden.state).toBe(session.state);
		expect(callback.hidden.iss).toBe(issuer().issuer);
		const { answer } = await send(at, "/oauth/token", (nonce) =>
			rp.token(session, callback.hidden.code ?? "", nonce),
		);
		expect(answer.status, answer.text).toBe(200);
		expect(answer.json).toMatchObject({ token_type: "DPoP" });
		for (const token of ["access_token", "id_token", "refresh_token"])
			expect(answer.json[token], token).toBeTypeOf("string");
		const claims = JSON.parse(
			Buffer.from(String(answer.json.access_token).split(".")[1] ?? "", "base64url").toString(),
		);
		expect(claims.cnf).toEqual({ jkt: session.dpopJkt });

		// The refresh family is bound to the session's key: the same key is taken, another refused.
		const refreshToken = String(answer.json.refresh_token);
		const same = await send(at, "/oauth/token", (nonce) =>
			rp.refresh(session, refreshToken, nonce),
		);
		expect(same.answer.status, same.answer.text).toBe(200);
		const other = { ...session, proof: dpopKey().proof };
		const moved = await send(at, "/oauth/token", (nonce) => rp.refresh(other, refreshToken, nonce));
		expect(moved.answer.status, moved.answer.text).toBe(400);
		expect(moved.answer.json).toMatchObject({
			error: "invalid_grant",
			error_description: "invalid refresh token",
		});
	});

	it("sends the person's denial to the RP: access_denied with T's state and issuer, and no code", async () => {
		carrying = "form_post";
		const { session, requestUri } = await pushed();
		const callback = callbackOf(await press(await shown(requestUri), "deny"));
		expect(callback.action).toBe(redirectUri);
		expect(callback.hidden).toEqual({
			error: "access_denied",
			state: session.state,
			iss: issuer().issuer,
		});
	});

	it("carries the Core's refusal of the finish to the RP, as a denial: its word, T's state and issuer (OIDC Core §3.1.2.6)", async () => {
		carrying = "form_post";
		const { session, requestUri } = await pushed();
		finishAnswer = {
			status: 400,
			body: { error: "login_required", error_description: "another subject" },
		};
		try {
			const callback = callbackOf(await press(await shown(requestUri), "approve"));
			expect(callback.action).toBe(redirectUri);
			expect(callback.hidden).toEqual({
				error: "login_required",
				state: session.state,
				iss: issuer().issuer,
			});
			expect(lastSeen()).toMatchObject({
				kind: "refused",
				refuser: "provider",
				at: "/login/finish",
				status: 400,
				error: "login_required",
				description: "another subject",
				carried: true,
			});
			// The moment's word is no answer of the authorization's: the screen's own page, nothing carried.
			const { requestUri: again } = await pushed();
			finishAnswer = { status: 503, body: { error: "temporarily_unavailable" } };
			const ended = await press(await shown(again), "approve");
			expect(ended.headers.location).toBe("/refused");
			expect(lastSeen()).toMatchObject({ refuser: "provider", error: "temporarily_unavailable" });
			expect(lastSeen()).not.toHaveProperty("carried");
		} finally {
			finishAnswer = undefined;
		}
	});

	it("carries the answer in a query where the run says so, the redirect URI's own query kept", async () => {
		carrying = "query";
		try {
			const { session, requestUri } = await pushed();
			const answered = await press(await shown(requestUri), "approve");
			expect(answered.status).toBe(302);
			const location = new URL(String(answered.headers.location));
			expect(`${location.origin}${location.pathname}`).toBe("https://rp.example.invalid/cb");
			expect(Object.fromEntries(location.searchParams)).toMatchObject({
				dummy1: "lorem",
				dummy2: "ipsum",
				state: session.state,
				iss: issuer().issuer,
			});
			expect(location.searchParams.get("code")).toBeTruthy();
		} finally {
			carrying = "form_post";
		}
	});

	it("sends a refused start to its own page, keeping the provider's answer as it was given", async () => {
		const unknown = "urn:ietf:params:oauth:request_uri:not-one-given";
		const direct = await role?.startPushed(post, rp.clientId, unknown);
		if (direct === undefined || !stopped(direct) || direct.stopped !== "provider")
			throw new Error(`the provider took ${unknown}`);
		const body = direct.body as Record<string, unknown>;
		const query = new URLSearchParams({
			client_id: rp.clientId,
			request_uri: unknown,
			state: "s-1",
		});
		const answered = await ask(atPages(), `/authorize?${query}`);
		expect(answered.status).toBe(302);
		expect(answered.headers.location).toBe("/refused");
		expect((await ask(atPages(), "/refused")).text).toContain('id="refused"');
		expect(lastSeen()).toEqual({
			kind: "refused",
			requestUri: unknown,
			state: "s-1",
			refuser: "provider",
			at: "/login/start",
			status: direct.status,
			error: body.error,
			description: body.error_description,
		});
	});

	it("sends a start with no request_uri to the provider as it came, its refusal the table's words", async () => {
		const query = new URLSearchParams({ client_id: rp.clientId, state: "s-2" });
		const answered = await ask(atPages(), `/authorize?${query}`);
		expect(answered.headers.location).toBe("/refused");
		const word = words.find(
			(w) => w.key === "jar-required" && w.description.includes("exactly one of its ways"),
		);
		expect(lastSeen()).toMatchObject({
			kind: "refused",
			requestUri: undefined,
			state: "s-2",
			refuser: "provider",
			at: "/login/start",
			error: word?.error,
			description: word?.description,
		});
	});

	it("sends a decision that does not go through to /refused, and keeps why", async () => {
		// The same page pressed twice: the second finds no start open.
		const { requestUri } = await pushed();
		const page = await shown(requestUri);
		await press(page, "deny");
		const again = await press(page, "deny");
		expect(again.headers.location).toBe("/refused");
		expect(lastSeen()).toMatchObject({ refuser: "page", stop: "no start open under this id" });

		// Neither button: nothing approved.
		const next = await shown((await pushed()).requestUri);
		const form = formsOf(next.text).find((f) => f.id === "decision");
		const unpressed = await ask(atPages(), "/decide", { method: "POST", form: form?.hidden ?? {} });
		expect(unpressed.headers.location).toBe("/refused");
		expect(lastSeen()).toMatchObject({ refuser: "page", stop: "neither approve nor deny" });

		// An approval the browser cannot give (it holds no passkey): kept as the browser's, with its request_uri.
		const held = role;
		const { requestUri: elsewhere } = await pushed();
		const page2 = await shown(elsewhere);
		try {
			role = loginScreen(
				() => ({ ring: [], issuer: issuer().issuer }),
				browser(pages?.origin ?? ""),
			);
			const refused = await press(page2, "approve");
			expect(refused.headers.location).toBe("/refused");
			expect(lastSeen()).toMatchObject({ kind: "refused", requestUri: elsewhere });
			expect(lastSeen()).not.toMatchObject({ refuser: "provider" });
		} finally {
			role = held;
		}
	});
});

describe("the provider's apps, through logins, a token and its refresh, every Core call relayed by the Front", () => {
	it("ran held by the permission model in audit, reaching nothing its grants do not cover, to its stop", async () => {
		const ran = issuer();
		// Stopped first, so each server's drain is in what it wrote; the scene's stop is once, its later calls nothing.
		await ran.stop();
		const audit = heldUnderAudit(ran.outputs());
		expect(audit.servers).toEqual(["nextgen-core", "nextgen-front"]);
		expect(audit.held, ran.output()).toEqual(["nextgen-core", "nextgen-front"]);
		expect(audit.events, ran.output()).toEqual([]);
		// Its time bounds the scene's stop it awaits: two servers, each stopped within create-app's
		// `stopWithinMs` (10 s, `apps.ts`) before SIGKILL, so 20 s, inside the 30 s of the afterAll the stop
		// came from. Should `stopWithinMs` change, this changes with it.
	}, 30_000);
});
