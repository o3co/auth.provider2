import { generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import type { Written } from "@mod/authority-rules/testing";
import { logTyps } from "@mod/transparency-wire";
import { challengeOf } from "@sdk/login-screen";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type Flow,
	type InProcess,
	inProcess,
	testClock,
} from "../../../in-process/test/in-process.ts";
import { readyWithinMs } from "../../../pattern/test/launch.ts";
import { previousKid } from "../../../pattern/test/pattern.ts";
import { honestRelay } from "../../../relay/relay.ts";
import { type Browser, browser } from "../../../roles/test/browser.ts";
import type { RelyingParty } from "../../../roles/test/rp.ts";
import { stopped } from "../../../roles/test/screen.ts";
import { screenOrigin } from "../../../world/test/world.ts";
import {
	flowOf,
	heldLogin,
	holding,
	loginProbe,
	records,
	refusalOf,
	sha256,
} from "../../test/kit.ts";
import { expectSwept, ledgerOf } from "../../test/sweep.ts";

// The keys group, K-7a to K-10r: a bad writer places a record whose key the flow
// does not hold, or holds otherwise (M), and beside it the same with the attack's one point undone (U).

const honestly = { verdict: "unsupported", outcome: "took" };
const forged = { verdict: "forged", outcome: "didNotTake" };
const rpId = new URL(screenOrigin).hostname;
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** Places a record as the bad writer, kept in its Core's ledger: its id, and the log's judgment of it. */
const place = (core: InProcess, flow: Flow, record: Written) => ledgerOf(core).placed(flow, record);

/** A passkey's assertion over a statement, made by the authenticator `device` holds `credential` on. */
async function assertionBy(device: Browser, credential: string, statement: string) {
	return device.get({
		challenge: await challengeOf(statement, "get"),
		rpId,
		allowCredentials: [{ type: "public-key", id: Buffer.from(credential, "base64url") }],
		userVerification: "required",
	});
}

/** A statement's payload signed again, as a JWS of its header's `typ` under `kid`, by `key`. */
function resigned(statement: string, key: KeyObject, kid: string) {
	const [head = "", payload = ""] = statement.split(".");
	const header = { ...JSON.parse(Buffer.from(head, "base64url").toString()), kid };
	const input = `${b64(header)}.${payload}`;
	const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
	return `${input}.${signature.toString("base64url")}`;
}

/** A first key's evidence on the mail's path, unspent: its `/key/finish` held back, read off the requests sent and the keys' owner. */
async function heldFirstKey(
	core: InProcess,
	subject: string,
	identifier: string,
	except: string[],
) {
	const w = core.world;
	const honest = await w.front();
	const device = browser(screenOrigin);
	const screen = w.screenOf(device);
	const started = await screen.firstKeyStart(honest, identifier);
	if (stopped(started)) throw new Error(`start: ${JSON.stringify(started)}`);
	const token = await w.firstKeyToken(identifier, except);
	const side = await screen.firstKeyMail(honest, { token, identifier, code: started.code });
	if (stopped(side)) throw new Error(`mail: ${JSON.stringify(side)}`);
	const stop = holding(honest, ["/key/finish"]);
	const kept = await screen.register(stop.front, side.creation, side.keys);
	if (!stopped(kept) || kept.at !== "/key/finish")
		throw new Error(`register: ${JSON.stringify(kept)}`);
	const register = stop.sent.find((s) => s.path === "/continue" && s.body.stage === "register");
	const finish = stop.held[0];
	const pending = (await core.keysRead.heldBy(subject)).pending;
	if (register === undefined || finish === undefined || pending === undefined)
		throw new Error("no register, finish or reservation");
	const creation = register.body.statement ?? "";
	return {
		token,
		device,
		screen,
		finish,
		reservation: pending.reservation,
		/** The key generation its signed creation names. */
		kg: JSON.parse(Buffer.from(creation.split(".")[1] ?? "", "base64url").toString()).creation.kg,
		ceremony: {
			creation,
			continuation: {
				seq: Number(register.body.seq ?? "1"),
				body: register.body.body ?? "",
				signature: register.body.sig ?? "",
			},
			possession: finish.body.statement ?? "",
			assertion: finish.body.assertion ?? "",
			credential: pending.credential,
			publicKey: pending.publicKey,
		},
	};
}

/** An embedder's recovery service's key: its public JWK with its kid, and instructions signed by it. */
function recoveryKey(kid = "reset-1") {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid, alg: "ES256" };
	const signed = (payload: unknown) => {
		const input = `${b64({ alg: "ES256", typ: logTyps.resetInstruction, kid })}.${b64(payload)}`;
		const signature = sign("sha256", Buffer.from(input), {
			key: pair.privateKey,
			dsaEncoding: "ieee-p1363",
		});
		return `${input}.${signature.toString("base64url")}`;
	};
	return { jwk, signed };
}
const installation = "install-k10";
const instructionFor = (subject: string, nowMs: number, kg: number) => ({
	v: 1,
	installation,
	subject,
	action: "reset",
	kg,
	id: randomBytes(16).toString("base64url"),
	iat: Math.floor(nowMs / 1000),
	exp: Math.floor(nowMs / 1000) + 600,
});

describe("a key the flow holds otherwise (K-7a, K-9)", () => {
	const previous = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	let core: InProcess;
	let rp: RelyingParty;
	beforeAll(async () => {
		core = await inProcess(
			{
				clientIds: ["rp-keys"],
				previousCoreKey: previous.export({ type: "pkcs8", format: "pem" }) as string,
			},
			honestRelay,
		);
		rp = core.world.rps[0] as RelyingParty;
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	it("K-7a: an approval of the victim's key carrying another's assertion is forged, the victim's own taking (NO_CHAIN_CHECK)", async () => {
		const victim = await core.world.person();
		const thief = await core.world.person();
		const { flow } = await flowOf(core, victim.credential);
		const login = await heldLogin(core, victim, rp, victim.credential);
		// The thief's passkey asserts the victim's T: a real assertion, by a key not the parent's.
		const theirs = await assertionBy(thief.browser, thief.credential, login.by.statement);
		const code = sha256("k7a-code");
		expect(
			(
				await place(
					core,
					flow,
					records.approval(flow, "k7a-m", { ...login.by, assertion: theirs }, code),
				)
			).judged,
		).toEqual(forged);
		expect(
			(await place(core, flow, records.approval(flow, "k7a-u", login.by, code))).judged,
		).toEqual(honestly);
		expect(refusalOf(await loginProbe(core, victim, rp))).toBe("temporarily_unavailable");
	});

	it("K-9: an approval of a T signed by the ring's earlier generation is forged, the writer's own taking (ringAny)", async () => {
		const victim = await core.world.person();
		const { flow } = await flowOf(core, victim.credential);
		const login = await heldLogin(core, victim, rp, victim.credential);
		// T signed again by the key of generation 1, which the screen pins too, and asserted by the victim's key.
		const earlier = resigned(login.by.statement, previous, previousKid);
		const asserted = await assertionBy(victim.browser, victim.credential, earlier);
		const code = sha256("k9-code");
		expect(
			(
				await place(
					core,
					flow,
					records.approval(
						flow,
						"k9-m",
						{ ...login.by, statement: earlier, assertion: asserted },
						code,
					),
				)
			).judged,
		).toEqual(forged);
		expect(
			(await place(core, flow, records.approval(flow, "k9-u", login.by, code))).judged,
		).toEqual(honestly);
		expect(refusalOf(await loginProbe(core, victim, rp))).toBe("temporarily_unavailable");
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 4, forged: 2, records: 6 }));
});

describe("a first key on a flow that holds one, and a key the keys' owner does not (K-8b, K-8a, K-7b)", () => {
	const identifier = "k8@mail.example";
	const subject = "k8";
	const clock = testClock();
	let core: InProcess;
	let rp: RelyingParty;
	beforeAll(async () => {
		core = await inProcess(
			{ clientIds: ["rp-k8"], seeds: [{ subject, identifier, verifiedEmail: identifier }] },
			honestRelay,
			clock,
		);
		rp = core.world.rps[0] as RelyingParty;
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	it("K-8b, K-8a, K-7b: takes E2's first trust as the residual, refuses E1's beside it, and refuses an approval by a key the keys' owner does not hold", async () => {
		const flow = { of: "subject", id: subject } as const;
		const e1 = await heldFirstKey(core, subject, identifier, []);
		// E1's reservation let lapse, for a second (another credential) under a reservation of its own.
		clock.advance(11 * 60_000);
		const e2 = await heldFirstKey(core, subject, identifier, [e1.token]);
		expect(e2.reservation).not.toBe(e1.reservation);
		const waiting = (await core.keysRead.heldBy(subject)).pending;
		// Another login's T, asserted by E2's key, held back before the bad writer places a record.
		const front = await core.world.front();
		const stop = holding(front, ["/login/finish"]);
		const who = { browser: e2.device, screen: e2.screen, credential: e2.ceremony.credential };
		const { s } = await core.world.started(who, rp, stop.front);
		expect(await e2.screen.approve(stop.front, s, [e2.ceremony.credential])).toMatchObject({
			stopped: "front",
			at: "/login/finish",
		});
		const t = stop.held[0];
		if (t === undefined) throw new Error("no finish held");
		// K-8b: E2's first trust, as an honest first key's: the residual, unsupported and taken (gap_first_trust).
		const first = await place(core, flow, records.firstKey(flow, e2.reservation, e2.ceremony));
		expect(first.judged).toEqual(honestly);
		// K-8a: E1's first trust on the flow that now holds E2's key: forged (EvilWrite ft).
		expect(
			(await place(core, flow, records.firstKey(flow, e1.reservation, e1.ceremony))).judged,
		).toEqual(forged);
		// K-7b: an approval rooted in E2's key, which the keys' owner does not hold: forged (holds).
		const approval = records.approval(
			flow,
			"k7b-m",
			{
				registration: first.id,
				statement: t.body.statement ?? "",
				assertion: t.body.assertion ?? "",
			},
			sha256("k7b-code"),
		);
		expect((await place(core, flow, approval)).judged).toEqual(forged);
		// The Core's side, once: E2's own finish (its reservation alive) stalls, and no key is taken in.
		const finished = await (await core.world.front()).post(e2.finish);
		expect(finished).toMatchObject({ status: 503, body: { error: "temporarily_unavailable" } });
		expect(finished.wire?.outcome).toBe("refused");
		const held = await core.keysRead.heldBy(subject);
		expect(held.credentials).toEqual([]);
		expect(await core.keysRead.keyOf(e1.ceremony.credential)).toBeUndefined();
		expect(await core.keysRead.keyOf(e2.ceremony.credential)).toBeUndefined();
		// E2 waits on its reservation as it did: not taken in, nor let go.
		expect(waiting).toMatchObject({
			reservation: e2.reservation,
			credential: e2.ceremony.credential,
			publicKey: e2.ceremony.publicKey,
		});
		expect(held.pending).toEqual(waiting);
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 3, forged: 2, records: 3 }));
});

describe("a key generation moved on, and the bad writer's own resets (K-10, K-10r)", () => {
	const recovery = recoveryKey();
	const clock = testClock();
	const seed = (name: string) => ({
		subject: name,
		identifier: `${name}@mail.example`,
		verifiedEmail: `${name}@mail.example`,
	});
	let core: InProcess;
	beforeAll(async () => {
		core = await inProcess(
			{
				clientIds: ["rp-k10"],
				change: ["@mod/passkey-reset"],
				reset: { installation, keys: [{ version: 1, keys: [recovery.jwk] }] },
				seeds: [seed("k10"), seed("k10r")],
			},
			honestRelay,
			clock,
		);
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	it("K-10: a first key of a creation signed for the key generation before the reset is forged, the one after taking (RE23_reg_noBnd)", async () => {
		const subject = "k10";
		const identifier = `${subject}@mail.example`;
		const flow = { of: "subject", id: subject } as const;
		const e1 = await heldFirstKey(core, subject, identifier, []);
		expect(e1.kg).toBe(0);
		const setup = core.setup;
		if (setup === undefined) throw new Error("passkey-reset is composed");
		// The honest operator's reset, placed and taken in.
		expect(await setup.reset(recovery.signed(instructionFor(subject, clock.now(), 0)))).toBe(
			"placed",
		);
		clock.advance(11 * 60_000);
		const e2 = await heldFirstKey(core, subject, identifier, [e1.token]);
		expect(e2.kg).toBe(1);
		const waiting = (await core.keysRead.heldBy(subject)).pending;
		expect(
			(await place(core, flow, records.firstKey(flow, e1.reservation, e1.ceremony))).judged,
		).toEqual(forged);
		expect(
			(await place(core, flow, records.firstKey(flow, e2.reservation, e2.ceremony))).judged,
		).toEqual(honestly);
		const finished = await (await core.world.front()).post(e2.finish);
		expect(finished).toMatchObject({ status: 503, body: { error: "temporarily_unavailable" } });
		expect(finished.wire?.outcome).toBe("refused");
		const held = await core.keysRead.heldBy(subject);
		expect(held.credentials).toEqual([]);
		expect(await core.keysRead.keyOf(e1.ceremony.credential)).toBeUndefined();
		expect(await core.keysRead.keyOf(e2.ceremony.credential)).toBeUndefined();
		expect(waiting).toMatchObject({
			reservation: e2.reservation,
			credential: e2.ceremony.credential,
		});
		expect(held.pending).toEqual(waiting);
	});

	it("K-10r: the bad writer's reset sent again is answered as placed, and an old one after the generation moved on is not placed", async () => {
		const subject = "k10r";
		const flow = { of: "subject", id: subject } as const;
		const before = await core.writer.head(flow);
		const instruction = recovery.signed(instructionFor(subject, clock.now(), 0));
		expect(await ledgerOf(core).reset(flow, instruction)).toBe("placed");
		expect(await core.writer.head(flow)).toBe(before + 1);
		// The same instruction sent again: answered as placed, nothing placed twice.
		expect(await ledgerOf(core).reset(flow, instruction)).toBe("placed");
		expect(await core.writer.head(flow)).toBe(before + 1);
		// Another, of the generation the first moved past: not placed.
		const old = recovery.signed(instructionFor(subject, clock.now(), 0));
		expect(await ledgerOf(core).reset(flow, old)).toEqual({ refused: "generation" });
		expect(await core.writer.head(flow)).toBe(before + 1);
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 3, forged: 1, records: 4 }));
});
