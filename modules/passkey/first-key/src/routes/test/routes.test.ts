import { randomBytes } from "node:crypto";
import { requests } from "@mod/front-core-wire";
import { type Route, routes } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { BootRefused, contract, defineModule, isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { composed, type Given } from "../../../test/fixtures/composed.ts";
import { screenPoints } from "../../../test/fixtures/screen.ts";

const seen = contract<readonly Route[]>("seen-routes");
const collecting = defineModule(
	{ name: "collecting-routes", replicaSafe: true, takes: [routes] },
	(m) => [m.provide(seen).by((c) => c.collect(routes))],
);
const b64 = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString("base64url");
const opening: NonNullable<Given["keys"]> = {
	open: async () => ({
		kind: "opened",
		plaintext: new TextEncoder().encode(JSON.stringify({ identifier: "alice" })),
	}),
	seal: async () => ({ enc: new Uint8Array(65).fill(4), ct: new Uint8Array(30).fill(5) }),
};

async function path(given: Given = {}) {
	const { app } = await composed({
		...given,
		keys: opening as NonNullable<Given["keys"]>,
		modules: [collecting],
	});
	const all = app.get(seen);
	const at = (p: string) => all.find((r) => r.path === p) as Route;
	const post = (p: string, json: Record<string, unknown>) =>
		at(p).handle(testRequest({ method: "POST", path: p, json }));
	return { app, all, post };
}
const sealing = (nonce: string) => {
	const points = screenPoints();
	return {
		nonce,
		eEnc: b64(points.eEnc),
		eSigX: b64(points.eSigX),
		eSigY: b64(points.eSigY),
		enc: b64(randomBytes(65)),
		ct: b64(randomBytes(40)),
	};
};

describe("the first key's routes", () => {
	it("serves its nonce and its start, each counted per source and taking the screen's JSON across origins", async () => {
		const { all } = await path();
		const mine = all.filter((r) => r.path.startsWith("/first-key/"));
		expect(mine.map((r) => r.path).sort()).toEqual([
			"/first-key/mail",
			"/first-key/nonce",
			"/first-key/recover",
			"/first-key/start",
		]);
		for (const route of mine) {
			expect(route.method).toBe("POST");
			expect(route.takes).toEqual(["json"]);
			expect(route.uses).toHaveLength(1);
			expect(route.cors).toBeDefined();
		}
	});

	it("gives a stage's nonce, and refuses a stage of no name", async () => {
		const { post } = await path();
		const given = await post("/first-key/nonce", { stage: "start" });
		expect(given.status).toBe(200);
		expect((given.body as { json: { nonce: string } }).json.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect((await post("/first-key/nonce", { stage: "other" })).status).toBe(400);
		// A field sent as no text is not carried; a name the wire gives no field is ignored.
		expect((await post("/first-key/nonce", { stage: 0 })).status).toBe(400);
		expect((await post("/first-key/nonce", { stage: "start", extra: 1 })).status).toBe(200);
	});

	it("answers a start its sealed code, a nonce used again access_denied, and fields of another size invalid", async () => {
		const { app, post } = await path();
		await app.start();
		const nonce = (
			(await post("/first-key/nonce", { stage: "start" })).body as { json: { nonce: string } }
		).json.nonce;
		const request = sealing(nonce);
		const answered = await post("/first-key/start", request);
		expect(answered.status).toBe(200);
		expect(answered.body).toEqual({
			json: {
				sealed: { enc: b64(new Uint8Array(65).fill(4)), ct: b64(new Uint8Array(30).fill(5)) },
			},
		});
		expect((await post("/first-key/start", request)).body).toEqual({
			json: { error: "access_denied" },
		});
		const short = { ...sealing(nonce), eSigX: b64(randomBytes(31)) };
		expect((await post("/first-key/start", short)).status).toBe(400);
		expect(
			((await post("/first-key/start", short)).body as { json: { error: string } }).json.error,
		).toBe("invalid_request");
		await app.stop();
	});
});

describe("the first key's start, its fields read as the wire sizes them", () => {
	it("fixes the sizes front-core-wire gives a sealed request, as the routes read them", () => {
		const sizes = Object.fromEntries(
			requests.firstKeyStart.fields.map((f) => [f.name, [f.min, f.max]]),
		);
		expect(sizes).toMatchObject({
			nonce: [43, 43],
			eEnc: [65, 65],
			eSigX: [32, 32],
			eSigY: [32, 32],
			enc: [65, 65],
			ct: [17, 2048],
		});
	});

	it("refuses a field not in its one spelling of base64url as invalid", async () => {
		const { post } = await path();
		const nonce = (
			(await post("/first-key/nonce", { stage: "start" })).body as { json: { nonce: string } }
		).json.nonce;
		const padded = { ...sealing(nonce), ct: `${sealing(nonce).ct}=` };
		expect((await post("/first-key/start", padded)).status).toBe(400);
		// Bits past the bytes set in its last character: another spelling of the same bytes.
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const ct = sealing(nonce).ct;
		const last = alphabet.indexOf(ct.slice(-1));
		const loose = { ...sealing(nonce), ct: `${ct.slice(0, -1)}${alphabet[last | 1]}` };
		expect((await post("/first-key/start", loose)).status).toBe(400);
	});

	it("answers unavailable where the keys' holder withdrew the Core's opening", async () => {
		const withdrawn: NonNullable<Given["keys"]> = {
			...opening,
			open: async () => ({ kind: "withdrawn" }),
		};
		const { app, all } = await composed({ keys: withdrawn, modules: [collecting] }).then(
			async (made) => ({ app: made.app, all: made.app.get(seen) }),
		);
		const at = (p: string) => all.find((r) => r.path === p) as Route;
		const nonce = (
			(
				await at("/first-key/nonce").handle(
					testRequest({ method: "POST", path: "/first-key/nonce", json: { stage: "start" } }),
				)
			).body as { json: { nonce: string } }
		).json.nonce;
		await expect(
			at("/first-key/start").handle(
				testRequest({ method: "POST", path: "/first-key/start", json: sealing(nonce) }),
			),
		).rejects.toSatisfy(isUnavailable);
		void app;
	});
});

describe("the first key's mail's side route", () => {
	it("fixes the sizes front-core-wire gives the mail's side and a recovery, as the routes read them", () => {
		const sizes = (fields: readonly { name: string; min: number; max: number }[]) =>
			Object.fromEntries(fields.map((f) => [f.name, [f.min, f.max]]));
		expect(sizes(requests.firstKeyMail.fields)).toEqual(sizes(requests.firstKeyStart.fields));
		expect(sizes(requests.firstKeyRecover.fields)).toMatchObject({
			nonce: [43, 43],
			digest: [43, 43],
			sig: [64, 64],
		});
	});

	it("answers a mail's side of fields of another size as invalid, and one its token refuses access_denied", async () => {
		const { post } = await path();
		const nonce = (
			(await post("/first-key/nonce", { stage: "mail" })).body as { json: { nonce: string } }
		).json.nonce;
		const short = { ...sealing(nonce), eSigY: b64(randomBytes(31)) };
		expect((await post("/first-key/mail", short)).status).toBe(400);
		expect((await post("/first-key/mail", sealing(nonce))).body).toEqual({
			json: { error: "access_denied" },
		});
	});
});

describe("the first key's mail's side, as its token refuses it", () => {
	const mailOpening = (plain: unknown): NonNullable<Given["keys"]> => ({
		...opening,
		open: async () => ({
			kind: "opened",
			plaintext: new TextEncoder().encode(JSON.stringify(plain)),
		}),
	});
	const found = {
		byIdentifier: async () => ({ kind: "user", user: { subject: "s-a", attributes: {} } }),
	};

	it("answers a token never issued access_denied, writing why in its reason's word alone", async () => {
		const plain = { token: "never-issued", identifier: "alice@example.com", code: "12345678" };
		const made = await composed({
			keys: mailOpening(plain),
			users: found as never,
			modules: [collecting],
		});
		const at = (p: string) => made.app.get(seen).find((r) => r.path === p) as Route;
		const post = (p: string, json: Record<string, unknown>) =>
			at(p).handle(testRequest({ method: "POST", path: p, json }));
		const nonce = (
			(await post("/first-key/nonce", { stage: "mail" })).body as { json: { nonce: string } }
		).json.nonce;
		expect((await post("/first-key/mail", sealing(nonce))).body).toEqual({
			json: { error: "access_denied" },
		});
		const line = made.recorded.lines().find((l) => l.event === "first-key.mail_refused");
		expect(line?.fields).toEqual({ refused: "token" });
		expect(JSON.stringify(made.recorded.lines())).not.toContain("alice");
	});
});

describe("the first key's recovery route", () => {
	it("refuses a recovery of fields of another size as invalid, and one kept for none in one word", async () => {
		const { post } = await path();
		const fields = {
			nonce: b64(randomBytes(32)),
			digest: b64(randomBytes(32)),
			sig: b64(randomBytes(64)),
		};
		expect(
			(await post("/first-key/recover", { ...fields, sig: b64(randomBytes(63)) })).status,
		).toBe(400);
		expect((await post("/first-key/recover", fields)).body).toEqual({
			json: { error: "access_denied" },
		});
	});
});

describe("the first key's path at boot", () => {
	it("is refused where users looks no one up by identifier, no passkey witness is composed, or webauthn takes no ceremony from the mail link's origin", async () => {
		const asked: string[] = [];
		const elsewhere = {
			ceremonies: {
				allowsOrigin: (origin: string) => {
					asked.push(origin);
					return false;
				},
			},
		};
		for (const given of [
			{ users: { byIdentifier: undefined } },
			{ witness: false },
			elsewhere,
		] as Given[]) {
			const refused = await composed(given).catch((error: unknown) => error);
			expect(BootRefused.is(refused)).toBe(true);
			expect((refused as BootRefused).refusals[0]?.where).toBe("first-key");
		}
		// The link's origin alone, not its path, is asked.
		expect(asked).toEqual(["https://login.example"]);
	});
});
