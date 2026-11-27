import { requests } from "@mod/front-core-wire";
import { firstKey, type ScreenKeys, screenKeys } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { BadFront } from "../../front/front.ts";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { type Browser, browser } from "../../roles/test/browser.ts";
import { stopped } from "../../roles/test/screen.ts";
import { payloadOf, thiefAssertion, thiefBody } from "./thief.ts";
import { origin, screenOrigin, type World, world } from "./world.ts";

// The compromised Front on a first key's path (F-15, F-15b, F-15c): users an operator brought, each
// holding no passkey, one per step; the mail goes apart from the Front, to the person's mailbox.

const names = ["ana", "bo", "cy", "di", "ed", "fi", "gu", "hu", "io", "jo", "ky"] as const;
type Name = (typeof names)[number];
const identifier = (name: Name) => `${name}@mail.example`;
const seeds = names.map((name, i) => ({
	subject: `${i + 1}`.padStart(32, "0"),
	identifier: identifier(name),
	verifiedEmail: identifier(name),
}));

let w: World;
beforeAll(async () => {
	w = await world(["rp-first"], { seeds });
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];

/** The token of the first-key mail sent to `name`. */
const tokenOf = (name: Name) => w.firstKeyToken(identifier(name));

/** A start through `front` on a screen of its own, and the mail it sent: what the page then seals on the mail's side. */
async function mailed(name: Name, front: BadFront, b: Browser = browser(screenOrigin)) {
	const screen = w.screenOf(b);
	const started = await screen.firstKeyStart(front, identifier(name));
	if (stopped(started)) throw new Error(`a start: ${JSON.stringify(started)}`);
	const plain = { token: await tokenOf(name), identifier: identifier(name), code: started.code };
	return { screen, plain };
}

/** A login at the RP with the credential given, through an honest Front: the callback, or where it stopped. */
async function login(b: Browser, credential: string) {
	const front = await w.front();
	const screen = w.screenOf(b);
	const s = await screen.start(front, rp().clientId, rp().authorization().jar);
	if (stopped(s)) return s;
	return screen.approve(front, s, [credential]);
}

/** The path's refusals the Core logs (`event:reason`): the wire's answer names none, `access_denied` alone. */
const reasons: Readonly<Record<string, string>> = {
	"first-key.mail_refused": "refused",
	"passkey-management.continue_refused": "reason",
	"passkey-management.registration_refused": "reason",
};
const refusalsLogged = () =>
	w.core.lines().flatMap((line) => {
		const field = reasons[line.event];
		if (field === undefined) return [];
		const stage = line.fields.stage === undefined ? "" : `${line.fields.stage}:`;
		return [`${line.event.slice(line.event.indexOf(".") + 1)}:${stage}${line.fields[field]}`];
	});
/** A step's value and the refusals the Core logs while it runs, waited for as the log comes apart from the wire. */
async function loggedDuring<T>(step: () => Promise<T>, count: number) {
	const before = refusalsLogged().length;
	const value = await step();
	await w.core.lineWhere(() => refusalsLogged().length >= before + count);
	return { value, logged: refusalsLogged().slice(before) };
}

/** What the Front saw, its bytes read as text: a plaintext crossing it would show here. */
const seenText = (front: BadFront) =>
	JSON.stringify(front.seen(), (_key, value) => {
		if (value instanceof Uint8Array) return Buffer.from(value).toString("latin1");
		// A statement (a compact JWS) is signed, not sealed: its header and payload read as text too.
		if (typeof value === "string" && /^[\w-]+\.[\w-]+\.[\w-]*$/.test(value)) {
			const [header = "", payload = ""] = value.split(".");
			const text = (part: string) => Buffer.from(part, "base64url").toString("utf8");
			return `${value} ${text(header)} ${text(payload)}`;
		}
		return value;
	});

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
/** The screen's public keys as a sealed request names them on the wire: all the Front holds of them. */
const keysOn = (message: { eEnc: Uint8Array; eSigX: Uint8Array; eSigY: Uint8Array }) =>
	({
		eEnc: b64url(message.eEnc),
		eSig: { kty: "EC", crv: "P-256", x: b64url(message.eSigX), y: b64url(message.eSigY) },
	}) as unknown as ScreenKeys;

describe("the first key, honest", () => {
	it("a brought user's first key, then a login with it; the Front sees no identifier, code or token", async () => {
		const b = browser(screenOrigin);
		const front = await w.front();
		const { screen, plain } = await mailed("ana", front, b);
		const key = await screen.firstKey(front, plain);
		if (stopped(key)) throw new Error(JSON.stringify(key));
		expect(await login(b, key.credential)).toHaveProperty("code");
		// MAIL_PLAINTEXT, CODE_PLAIN: the start and the mail's side are sealed, their answers too.
		const seen = seenText(front);
		for (const secret of [plain.identifier, plain.code, plain.token])
			expect(seen).not.toContain(secret);
	});
});

describe("the compromised Front on the first key (F-15)", () => {
	it("hole B: the mail's side rewrapped with the Front's own link is refused by the SDK's readCreation", async () => {
		// The Front's own account: its start and its mail, under a screen it runs.
		const own = await mailed("cy", await w.front());
		const front = await w.front();
		const victim = await mailed("bo", front);
		// The victim's sealed request replaced by the Front's own, sealed under the victim's nonce and public keys.
		front.rewrite({
			messages: {
				firstKeyMail: async (message) => {
					const made = await firstKey.mail(own.plain, message.nonce, {
						ring: w.core.ring,
						issuer: origin,
						sealingKey: w.sealingKey,
						keys: keysOn(message),
					});
					if ("error" in made) throw new Error(made.error);
					return { ...message, enc: made.mail.sealed.enc, ct: made.mail.sealed.ct };
				},
			},
		});
		expect(await victim.screen.firstKey(front, victim.plain)).toMatchObject({
			stopped: "sdk",
			at: "firstKey.readCreation",
			error: "evidence",
		});
	});

	it("NO_AAD_EKEYS: the screen's keys swapped beside a sealed request fail its opening, at the start and on the mail's side", async () => {
		const theirs = await screenKeys();
		const swap = <M extends { eEnc: Uint8Array; eSigX: Uint8Array; eSigY: Uint8Array }>(
			m: M,
		): M => ({
			...m,
			eEnc: Buffer.from(theirs.eEnc, "base64url"),
			eSigX: Buffer.from(theirs.eSig.x, "base64url"),
			eSigY: Buffer.from(theirs.eSig.y, "base64url"),
		});
		const atStart = await w.front();
		atStart.rewrite({ messages: { firstKeyStart: swap } });
		const started = await w
			.screenOf(browser(screenOrigin))
			.firstKeyStart(atStart, identifier("di"));
		expect(started).toMatchObject({ stopped: "core", at: "/first-key/start" });
		const atMail = await w.front();
		const { screen, plain } = await mailed("ed", atMail);
		atMail.rewrite({ messages: { firstKeyMail: swap } });
		const side = await loggedDuring(() => screen.firstKeyMail(atMail, plain), 1);
		// The start not opened put no job: no mail went to its identifier, by the time another's came.
		expect(w.core.mail().filter((m) => m.to === identifier("di"))).toEqual([]);
		expect(side.value).toMatchObject({ stopped: "core", at: "/first-key/mail" });
		expect(side.logged).toEqual(["mail_refused:unopened"]);
	});

	it("the register stage's key swapped for the Front's own is refused: only E_sig signs the stage", async () => {
		const front = await w.front();
		const { screen, plain } = await mailed("fi", front);
		const thief = browser(screenOrigin);
		front.rewrite({
			messages: {
				continue: async (message) =>
					message.stage === 0
						? { ...message, body: await thiefBody(thief, message.statement) }
						: message,
			},
		});
		const keyed = await loggedDuring(() => screen.firstKey(front, plain), 1);
		expect(keyed.value).toMatchObject({ stopped: "core", at: "/continue register" });
		expect(keyed.logged).toEqual(["continue_refused:register:signature"]);
	});

	it("SUBJECT_FROM_WIRE: no request of the path carries a subject or an identifier the Core could take", () => {
		// A field of no signature, that is: a `statement` carries a subject, signed by the Core's ring.
		const path = [
			"firstKeyNonce",
			"firstKeyStart",
			"firstKeyMail",
			"continue",
			"keyFinish",
		] as const;
		for (const kind of path) {
			const fields = requests[kind].fields.map((f) => f.name.toLowerCase());
			expect(fields.filter((name) => /sub|ident|account|user/.test(name))).toEqual([]);
		}
	});
});

describe("F-15b: the mail's side naming another subject than its token's", () => {
	it("the Front's own token and code, sealed beside another user's identifier, are refused by the Core", async () => {
		const own = await mailed("gu", await w.front());
		const front = await w.front();
		const side = await loggedDuring(
			() => own.screen.firstKeyMail(front, { ...own.plain, identifier: identifier("hu") }),
			1,
		);
		expect(side.value).toMatchObject({ stopped: "core", at: "/first-key/mail" });
		// The token is tried against the identifier's subject: another's is the token's refusal.
		expect(side.logged).toEqual(["mail_refused:token"]);
		// The control: the same token and code beside their own identifier are taken.
		const taken = await own.screen.firstKeyMail(front, own.plain);
		expect(taken).toHaveProperty("creation");
	});
});

describe("F-15c: a key registered without its possession", () => {
	it("a key whose possession was never asserted is not one a login takes", async () => {
		const b = browser(screenOrigin);
		const front = await w.front();
		const { screen, plain } = await mailed("io", front, b);
		const side = await screen.firstKeyMail(front, plain);
		if (stopped(side)) throw new Error(JSON.stringify(side));
		// The page left after the register stage: the new key made, its get() never run.
		let made = "";
		const leaving: Browser = {
			...b,
			create: (options) => {
				const key = b.create(options);
				made = key.id;
				return key;
			},
			get: () => {
				throw new DOMException("the page left", "NotAllowedError");
			},
		};
		const registered = await screen.register(front, side.creation, side.keys, leaving);
		expect(registered).toMatchObject({ stopped: "browser", at: "get" });
		expect(made).not.toBe("");
		// The authenticator holds the key and asserts with it; the Core takes it for no login.
		expect(await login(b, made)).toMatchObject({ stopped: "core", at: "/login/finish" });
	});

	it("the possession asserted by another key than the new one is refused at the finish", async () => {
		const front = await w.front();
		const { screen, plain } = await mailed("jo", front);
		const thief = browser(screenOrigin);
		front.rewrite({
			messages: {
				keyFinish: async (message) => ({
					...message,
					assertion: await thiefAssertion(thief, message.statement, new URL(screenOrigin).hostname),
				}),
			},
		});
		const finished = await loggedDuring(() => screen.firstKey(front, plain), 1);
		expect(finished.value).toMatchObject({ stopped: "core", at: "/key/finish" });
		// The thief's credential is none the possession names, nor one the Core holds.
		expect(finished.logged).toEqual(["registration_refused:unknown"]);
	});

	it("the possession asserted by the thief's key under the new key's id is refused: the new key's signature is checked", async () => {
		const front = await w.front();
		const { screen, plain } = await mailed("ky", front);
		const thief = browser(screenOrigin);
		front.rewrite({
			messages: {
				keyFinish: async (message) => {
					const named = (payloadOf(message.statement).possession as { credential_id: string })
						.credential_id;
					return {
						...message,
						assertion: await thiefAssertion(
							thief,
							message.statement,
							new URL(screenOrigin).hostname,
							named,
						),
					};
				},
			},
		});
		const finished = await loggedDuring(() => screen.firstKey(front, plain), 1);
		expect(finished.value).toMatchObject({ stopped: "core", at: "/key/finish" });
		expect(finished.logged).toEqual(["registration_refused:signature"]);
	});
});
