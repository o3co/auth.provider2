import { decodeRequest, encodeRequest, type Message } from "@mod/front-core-codec";
import { headerLength } from "@mod/front-core-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readyWithinMs } from "../../../test/core/launch.ts";
import { loginScreen, stopped } from "../../../test/roles/screen.ts";
import { origin, screenOrigin, type World, world } from "./world.ts";

// The compromised Front's steps at the edges (the design note's §2): the origin a ceremony is made
// at (F-9), and frames no honest Front sends (F-19).

let w: World;
beforeAll(async () => {
	w = await world(["rp-edges"]);
}, readyWithinMs + 10_000);
afterAll(async () => {
	await w?.stop();
});

const rp = () => w.rps[0] as World["rps"][number];

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
		// An honest frame with a byte after its last field, its length saying so: the codec rejects it.
		const frame = encodeRequest("firstKeyNonce", 7, honest);
		const bad = new Uint8Array(frame.length + 1);
		bad.set(frame);
		new DataView(bad.buffer).setUint32(6, frame.length + 1 - headerLength);
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
});
