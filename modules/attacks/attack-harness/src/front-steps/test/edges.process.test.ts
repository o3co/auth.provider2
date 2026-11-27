import { createHash } from "node:crypto";
import { decodeRequest, encodeRequest, type Message, type WireReply } from "@mod/front-core-codec";
import { headerLength, refusals } from "@mod/front-core-wire";
import { firstKey as words } from "@mod/sdk-core-wire";
import { answers } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { BadFront } from "../../front/front.ts";
import { readyWithinMs } from "../../pattern/test/launch.ts";
import { browser } from "../../roles/test/browser.ts";
import { loginScreen, stopped } from "../../roles/test/screen.ts";
import { origin, screenOrigin, type World, world } from "./world.ts";

// The compromised Front's steps at the edges (the design note's §2): the origin a ceremony is made
// at (F-9), frames no honest Front sends, and a stream cut: a frame left half sent, an answer lost
// (F-19). Users an operator brought take the first key's path where an answer is lost.

let w: World;
beforeAll(async () => {
	w = await world(["rp-edges"], { seeds: ["lo", "ma"].map(seed) });
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];

/** An honest frame with a byte after its last field, its length saying so: the codec rejects it. */
function trailing(message: Message<"firstKeyNonce">, id: number) {
	const frame = encodeRequest("firstKeyNonce", id, message);
	const bad = new Uint8Array(frame.length + 1);
	bad.set(frame);
	new DataView(bad.buffer).setUint32(6, frame.length + 1 - headerLength);
	return bad;
}

/** A brought user holding no passkey, by a name of its own. */
function seed(name: string, i: number) {
	const address = `${name}@mail.example`;
	return { subject: `e${i + 1}`.padStart(32, "0"), identifier: address, verifiedEmail: address };
}
/** A first key's start through `front`, and its mail's token: what the page then seals on the mail's side. */
async function mailed(name: string, front: BadFront, b = browser(screenOrigin)) {
	const identifier = `${name}@mail.example`;
	const screen = w.screenOf(b);
	const started = await screen.firstKeyStart(front, identifier);
	if (stopped(started)) throw new Error(`a start: ${JSON.stringify(started)}`);
	return {
		screen,
		plain: { token: await w.firstKeyToken(identifier), identifier, code: started.code },
	};
}
/** The statement of a reply the Core sent: its JSON answer, as bytes on the wire. */
const statementOf = (reply: WireReply) =>
	reply.outcome === "ok"
		? answers.read("statement", JSON.parse(Buffer.from(reply.message.body).toString("utf8")))
		: undefined;
/** The Front answering the page as if the Core's reply never came: the stream cut after the Core acted. */
const lost = (reply: WireReply): WireReply => ({
	outcome: "refused",
	id: reply.id,
	message: {
		error: refusals.indexOf("server_error") + 1,
		detail: "",
		dpopNonce: "",
		retryAfter: "",
	},
});

describe("the compromised Front at the edges", () => {
	it("F-9: the victim's passkey used on a page of another origin under the RP id: the Core's origin check refuses it", async () => {
		const victim = await w.person();
		const front = await w.front();
		// A page the Front serves at a subdomain: the browser lets it ask for the screen's RP id.
		const elsewhere = victim.browser.at("https://evil.login.example");
		const screen = loginScreen({ ring: w.core.ring, issuer: origin }, elsewhere, {
			rpId: new URL(screenOrigin).hostname,
		});
		const s = await screen.start(front, rp().clientId, rp().authorization().jar);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		const approved = await screen.approve(front, s, [victim.credential]);
		expect(approved).toMatchObject({
			stopped: "core",
			at: "/login/finish",
			answered: { body: { error: "access_denied" } },
		});
		// The same person, passkey and Front at the screen's own origin: approved, so the origin alone was refused.
		const own = await victim.screen.start(front, rp().clientId, rp().authorization().jar);
		if (stopped(own)) throw new Error(JSON.stringify(own));
		expect(stopped(await victim.screen.approve(front, own, [victim.credential]))).toBe(false);
	});

	it("F-19: a frame no honest Front sends is rejected and its connection ended; the Core serves the next", async () => {
		const wire = await w.connect();
		const honest: Message<"firstKeyNonce"> = { source: w.fresh(), stage: 0 };
		const bad = trailing(honest, 7);
		expect(decodeRequest(bad)).toMatchObject({ ok: false, id: 7 });
		const before = w.core.lines().filter((line) => line.event === "core-wire.violation").length;
		const reply = await wire.raw(bad, 7);
		expect(reply.outcome).toBe("rejected");
		await wire.closed;
		// The Core cuts nothing by default (`notify`): the same instance's next connection is served.
		const again = await w.connect();
		expect((await again.send("firstKeyNonce", 1, honest)).outcome).toBe("ok");
		// This frame's violation: one more than before it, warned.
		await w.core.lineWhere(
			() => w.core.lines().filter((line) => line.event === "core-wire.violation").length > before,
		);
		const violation = w.core.lines().filter((line) => line.event === "core-wire.violation")[before];
		expect(violation?.level).toBe("warn");
	});

	it(
		"F-19: a frame left half sent, its stream then ended, is no violation: under `cut`, its Front instance is served after it, as it is not after a frame no honest Front sends",
		async () => {
			// A Core of its own whose wire cuts a Front instance at its first violation: a violation shows
			// as the instance refused, no warning (held to one a minute) needed.
			const cutting = await world([], { onViolation: "cut" });
			try {
				const nonce = (): Message<"firstKeyNonce"> => ({ source: cutting.fresh(), stage: 0 });
				const wire = await cutting.connect();
				// The connection up and read: an honest frame answered on it first.
				expect((await wire.send("firstKeyNonce", 1, nonce())).outcome).toBe("ok");
				// Then a frame's first bytes, the stream ended after them (written first): the Core closes its
				// side once it read the end, every byte before it.
				const frame = encodeRequest("firstKeyNonce", 2, nonce());
				wire.socket.end(frame.subarray(0, frame.length - 4));
				await wire.closed;
				const next = await cutting.connect();
				// Answered, not closed: a half frame taken as a violation would cut the instance here.
				const answered = await Promise.race([
					next.send("firstKeyNonce", 1, nonce()).then((reply) => reply.outcome),
					next.closed.then(() => "closed"),
				]);
				expect(answered).toBe("ok");
				// The control: a frame no honest Front sends, and the same instance is cut.
				const bad = await cutting.connect();
				expect((await bad.raw(trailing(nonce(), 3), 3)).outcome).toBe("rejected");
				await bad.closed;
				await cutting.core.lineWhere((line) => line.event === "core-wire.cut");
				const after = await cutting.connect();
				await after.closed;
				await cutting.core.lineWhere((line) => line.event === "core-wire.cut_refused");
			} finally {
				await cutting.stop();
			}
		},
		readyWithinMs + 10_000,
	);

	it("F-19: a first key's creation whose answer was lost is recovered by the page that sealed it, the same bytes; never by another's keys", async () => {
		const b = browser(screenOrigin);
		const cut = await w.front();
		const { screen, plain } = await mailed("lo", cut, b);
		cut.rewrite({ replies: { firstKeyMail: lost } });
		const side = await screen.firstKeyMail(cut, plain);
		expect(side).toMatchObject({ stopped: "front", at: "/first-key/mail" });
		const kept = cut.seen().findLast((r) => r.kind === "firstKeyMail")?.reply;
		if (kept?.outcome !== "ok" || !("sent" in side) || side.sent === undefined)
			throw new Error("no creation the Core made");
		// The Front asks for it itself, the nonce and digest it saw, signed by a key of its own: refused.
		const thief = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
			"sign",
		]);
		// What the Front saw of the sealed request: its nonce, and the digest of its enc and ct.
		const seen = cut.seen().findLast((r) => r.kind === "firstKeyMail")
			?.message as Message<"firstKeyMail">;
		const nonce = seen.nonce;
		const digest = createHash("sha256").update(seen.enc).update(seen.ct).digest("base64url");
		// The very nonce and digest the page's own recovery signs below: only the signature differs.
		expect({ nonce, digest }).toEqual({
			nonce: side.sent.mail.nonce,
			digest: side.sent.mail.ctHash,
		});
		const forged = await crypto.subtle.sign(
			{ name: "ECDSA", hash: "SHA-256" },
			thief.privateKey,
			new TextEncoder().encode(words.recoverInput(nonce, digest)),
		);
		const theirs = await (await w.front()).post({
			path: "/first-key/recover",
			body: { nonce, digest, sig: Buffer.from(forged).toString("base64url") },
		});
		expect(theirs.status).toBe(400);
		const refusal = await w.core.lineWhere((line) => line.event === "first-key.recovery_refused");
		expect(refusal.fields).toEqual({ refused: "recovery" });
		// The page that sealed it asks again, the same nonce and digest under its own E_sig: the creation
		// the Core kept, the same bytes (so the refusal above was the signature alone), and the key goes on.
		const honest = await w.front();
		const recovered = await screen.firstKeyRecover(honest, side.sent);
		if (stopped(recovered)) throw new Error(JSON.stringify(recovered));
		expect(recovered.creation.compact).toBe(statementOf(kept));
		const key = await screen.register(honest, recovered.creation, recovered.keys);
		if (stopped(key)) throw new Error(JSON.stringify(key));
		const s = await screen.start(honest, rp().clientId, rp().authorization().jar);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		expect(await screen.approve(honest, s, [key.credential])).toHaveProperty("code");
	});

	it("F-19: a register stage whose answer was lost, sent again as it was, is answered the possession the Core kept", async () => {
		const b = browser(screenOrigin);
		const cut = await w.front();
		const { screen, plain } = await mailed("ma", cut, b);
		const side = await screen.firstKeyMail(cut, plain);
		if (stopped(side)) throw new Error(JSON.stringify(side));
		cut.rewrite({ replies: { continue: lost } });
		// The key create() made, kept as the page keeps it while it waits on the answer.
		let made: { id: string; spki: Uint8Array; alg: number } | undefined;
		const device = {
			...b,
			create: (options: PublicKeyCredentialCreationOptions) => {
				const key = b.create(options);
				made = key;
				return key;
			},
		};
		expect(await screen.register(cut, side.creation, side.keys, device)).toMatchObject({
			stopped: "front",
			at: "/continue register",
		});
		const sent = cut.seen().findLast((r) => r.kind === "continue");
		if (sent?.reply.outcome !== "ok") throw new Error("no possession the Core made");
		const message = sent.message as Message<"continue">;
		// The same request again, through another connection: the kept answer, not a second key.
		const again = await (await w.front()).post({
			path: "/continue",
			body: {
				statement: message.statement,
				stage: "register",
				seq: String(message.seq),
				body: message.body,
				sig: Buffer.from(message.sig).toString("base64url"),
			},
		});
		expect(again.status).toBe(200);
		const kept = statementOf(sent.reply);
		expect(kept).toBeTypeOf("string");
		expect(answers.read("statement", again.body)).toBe(kept);
		// The kept possession is the new key's: read against it, its get() and finish, and a login with it.
		if (made === undefined || kept === undefined) throw new Error("no key made");
		const key = await screen.possess(await w.front(), kept, side.creation, made, side.keys, b);
		if (stopped(key)) throw new Error(JSON.stringify(key));
		const honest = await w.front();
		const s = await screen.start(honest, rp().clientId, rp().authorization().jar);
		if (stopped(s)) throw new Error(JSON.stringify(s));
		expect(await screen.approve(honest, s, [key.credential])).toHaveProperty("code");
	});
});
