import type { Written } from "@mod/authority-rules/testing";
import { tokens } from "@mod/transparency-wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type Flow,
	type InProcess,
	inProcess,
	testClock,
} from "../../../in-process/test/in-process.ts";
import { signedMachine } from "../../../pattern/test/clients.ts";
import { readyWithinMs } from "../../../pattern/test/launch.ts";
import { honestRelay } from "../../../relay/relay.ts";
import { type MachineClient, machineClient } from "../../../roles/test/machine.ts";
import type { RelyingParty } from "../../../roles/test/rp.ts";
import { provider } from "../../../world/test/world.ts";
import {
	flowOf,
	heldLogin,
	loginProbe,
	records,
	refusalOf,
	sha256,
	tokenDigest,
} from "../../test/kit.ts";
import { expectSwept, ledgerOf } from "../../test/sweep.ts";

// The code and client group, K-11 to K-13, K-16, K-17: a bad writer places a start or a bundle its
// approval, its family or its client's evidence does not hold (M), and beside it one that does (U).

const honestly = { verdict: "unsupported", outcome: "took" };
const verified = { verdict: "verified", outcome: "took" };
const forged = { verdict: "forged", outcome: "didNotTake" };
const late = { verdict: "unsupported", outcome: "didNotTake" };
const api = "https://api.example";

/** Places a record as the bad writer, kept in its Core's ledger: its id, when the log took it, and its judgment; or the log's refusal. */
const place = (core: InProcess, flow: Flow, record: Written) => ledgerOf(core).place(flow, record);
/** As `place`, for a record the log must take. */
const placed = (core: InProcess, flow: Flow, record: Written) =>
	ledgerOf(core).placed(flow, record);

/** A bundle's tokens: an access token, and a refresh family where it makes one. */
const tokensOf = (seed: string, family = false) => [
	{ frame: "accessToken" as const, digest: tokenDigest(`${seed}-at`) },
	...(family ? [{ frame: "family" as const, digest: tokenDigest(`${seed}-family`) }] : []),
];

describe("a code's start and bundle its approval does not hold (K-11, K-12, K-17)", () => {
	let core: InProcess;
	let rp: RelyingParty;
	beforeAll(async () => {
		core = await inProcess({ clientIds: ["rp-codes"] }, honestRelay);
		rp = core.world.rps[0] as RelyingParty;
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	/** A person, their flow, and `n` logins approved by their key, held back, each with a code of its own. */
	async function approvals(n: number, name: string) {
		const who = await core.world.person();
		const { flow } = await flowOf(core, who.credential);
		const held = [];
		for (let i = 0; i < n; i++) held.push(await heldLogin(core, who, rp, who.credential));
		const codeOf = (i: number) => sha256(`${name}-code-${i}`);
		const via = (i: number) => ({ via: "code", code: codeOf(i), client: rp.clientId }) as const;
		return { who, flow, held, codeOf, via };
	}

	it("K-11: a code's start naming another code or client than its approval is forged, the approval's own taking (V24 (3))", async () => {
		const { who, flow, held, codeOf, via } = await approvals(3, "k11");
		const [one, two, three] = held as [
			(typeof held)[number],
			(typeof held)[number],
			(typeof held)[number],
		];
		const a1 = await placed(core, flow, records.approval(flow, one.op, one.by, codeOf(1)));
		const a2 = await placed(core, flow, records.approval(flow, two.op, two.by, codeOf(2)));
		const a3 = await placed(core, flow, records.approval(flow, three.op, three.by, codeOf(3)));
		expect([a1.judged, a2.judged, a3.judged]).toEqual([honestly, honestly, honestly]);
		const swapped = { ...via(1), code: sha256("k11-another-code") };
		expect((await placed(core, flow, records.start(flow, "k11-m", a1.id, swapped))).judged).toEqual(
			forged,
		);
		// Another client than approval 3's, on an approval no start has used yet.
		const elsewhere = { ...via(3), client: "another-client" };
		expect(
			(await placed(core, flow, records.start(flow, "k11-m2", a3.id, elsewhere))).judged,
		).toEqual(forged);
		expect((await placed(core, flow, records.start(flow, "k11-u", a2.id, via(2)))).judged).toEqual(
			honestly,
		);
		// What M burned, as the monitor sees it: approval 1's honest start is now its code's second exchange.
		expect(
			(await placed(core, flow, records.start(flow, "k11-after", a1.id, via(1)))).judged,
		).toEqual(forged);
		expect(refusalOf(await loginProbe(core, who, rp))).toBe("temporarily_unavailable");
	});

	it("K-12: a start and its bundle with no approval are forged, an approval's taking; two approvals of one code are not forged (C-7)", async () => {
		const { who, flow, held, codeOf, via } = await approvals(3, "k12");
		const [one, two, three] = held as [
			(typeof held)[number],
			(typeof held)[number],
			(typeof held)[number],
		];
		const { registration } = await flowOf(core, who.credential);
		// M rooted in the key's registration, which is no approval.
		const ms = await placed(core, flow, records.start(flow, "k12-m", registration, via(8)));
		expect(ms.judged).toEqual(forged);
		expect(
			(
				await placed(
					core,
					flow,
					records.bundle(flow, "k12-m", { start: ms.id, root: registration }, tokensOf("k12-m"), {
						via: "code",
					}),
				)
			).judged,
		).toEqual(forged);
		const a1 = await placed(core, flow, records.approval(flow, one.op, one.by, codeOf(1)));
		const us = await placed(core, flow, records.start(flow, "k12-u", a1.id, via(1)));
		const ub = await placed(
			core,
			flow,
			records.bundle(flow, "k12-u", { start: us.id, root: a1.id }, tokensOf("k12-u"), {
				via: "code",
			}),
		);
		expect([a1.judged, us.judged, ub.judged]).toEqual([honestly, honestly, honestly]);
		// Two approvals naming one code: neither is forged at L0 (V12; L1's apr closes it).
		const same = codeOf(9);
		const a2 = await placed(core, flow, records.approval(flow, two.op, two.by, same));
		const a3 = await placed(core, flow, records.approval(flow, three.op, three.by, same));
		expect([a2.judged, a3.judged]).toEqual([honestly, honestly]);
		expect(refusalOf(await loginProbe(core, who, rp))).toBe("temporarily_unavailable");
	});

	it("K-17: a bundle naming another approval as its root than its start's is forged, its start taking, the one rooted in its own taking (C-6)", async () => {
		const { who, flow, held, codeOf, via } = await approvals(2, "k17");
		const [one, two] = held as [(typeof held)[number], (typeof held)[number]];
		const a1 = await placed(core, flow, records.approval(flow, one.op, one.by, codeOf(1)));
		const a2 = await placed(core, flow, records.approval(flow, two.op, two.by, codeOf(2)));
		expect([a1.judged, a2.judged]).toEqual([honestly, honestly]);
		// M first: its bundle names approval 2, whose code no bundle has used yet.
		const ms = await placed(core, flow, records.start(flow, "k17-m", a1.id, via(1)));
		expect(ms.judged).toEqual(honestly);
		expect(
			(
				await placed(
					core,
					flow,
					records.bundle(flow, "k17-m", { start: ms.id, root: a2.id }, tokensOf("k17-m"), {
						via: "code",
					}),
				)
			).judged,
		).toEqual(forged);
		const us = await placed(core, flow, records.start(flow, "k17-u", a2.id, via(2)));
		const ub = await placed(
			core,
			flow,
			records.bundle(flow, "k17-u", { start: us.id, root: a2.id }, tokensOf("k17-u"), {
				via: "code",
			}),
		);
		expect([us.judged, ub.judged]).toEqual([honestly, honestly]);
		expect(refusalOf(await loginProbe(core, who, rp))).toBe("temporarily_unavailable");
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 20, forged: 6, records: 23 }));
});

describe("a start or a bundle past its time (K-16)", () => {
	const clock = testClock();
	let core: InProcess;
	let rp: RelyingParty;
	beforeAll(async () => {
		core = await inProcess({ clientIds: ["rp-time"] }, honestRelay, clock);
		rp = core.world.rps[0] as RelyingParty;
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	it("K-16: a code's start past the code's life does not take, its bundle forged; a bundle past the issue window does not take (BundleEscape023)", async () => {
		// Two flows: (a) a code's life, (b) the issue window; every approval held back first.
		const a = await core.world.person();
		const b = await core.world.person();
		const fa = (await flowOf(core, a.credential)).flow;
		const fb = (await flowOf(core, b.credential)).flow;
		const [a1, a2] = [
			await heldLogin(core, a, rp, a.credential),
			await heldLogin(core, a, rp, a.credential),
		];
		const [b3, b4] = [
			await heldLogin(core, b, rp, b.credential),
			await heldLogin(core, b, rp, b.credential),
		];
		const via = (n: string) =>
			({ via: "code", code: sha256(`k16-code-${n}`), client: rp.clientId }) as const;
		const approve = async (flow: Flow, login: typeof a1, n: string) =>
			placed(core, flow, records.approval(flow, login.op, login.by, via(n).code));
		const bundleOf = (flow: Flow, op: string, start: string, root: string) =>
			records.bundle(flow, op, { start, root }, tokensOf(op), { via: "code" });
		// (a) U in time: approval 2 redeemed.
		const p1 = await approve(fa, a1, "1");
		const p2 = await approve(fa, a2, "2");
		const u2 = await placed(core, fa, records.start(fa, "k16a-u", p2.id, via("2")));
		const u2b = await placed(core, fa, bundleOf(fa, "k16a-u", u2.id, p2.id));
		expect([p1.judged, p2.judged, u2.judged, u2b.judged]).toEqual([
			honestly,
			honestly,
			honestly,
			honestly,
		]);
		// (b) U in time: approval 4 redeemed; approval 3's start placed, its bundle not yet.
		const p3 = await approve(fb, b3, "3");
		const p4 = await approve(fb, b4, "4");
		const u4 = await placed(core, fb, records.start(fb, "k16b-u", p4.id, via("4")));
		const u4b = await placed(core, fb, bundleOf(fb, "k16b-u", u4.id, p4.id));
		const m3 = await placed(core, fb, records.start(fb, "k16b-m", p3.id, via("3")));
		expect([p3.judged, p4.judged, u4.judged, u4b.judged, m3.judged]).toEqual([
			honestly,
			honestly,
			honestly,
			honestly,
			honestly,
		]);
		// (b) M: the bundle past the issue window (1 minute).
		clock.advance(61_000);
		expect((await placed(core, fb, bundleOf(fb, "k16b-m", m3.id, p3.id))).judged).toEqual(late);
		// (a) M: approval 1's start past the code's life (10 minutes), and its bundle.
		clock.advance(10 * 60_000);
		const m1 = await placed(core, fa, records.start(fa, "k16a-m", p1.id, via("1")));
		expect(m1.judged).toEqual(late);
		expect((await placed(core, fa, bundleOf(fa, "k16a-m", m1.id, p1.id))).judged).toEqual(forged);
		expect(refusalOf(await loginProbe(core, a, rp))).toBe("temporarily_unavailable");
		expect(refusalOf(await loginProbe(core, b, rp))).toBe("temporarily_unavailable");
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 12, forged: 1, records: 14 }));
});

describe("a client's own flow (K-13)", () => {
	let core: InProcess;
	let machine: MachineClient;
	beforeAll(async () => {
		machine = machineClient("svc-k13", provider);
		core = await inProcess(
			{
				signedClients: [
					await signedMachine(machine.id, machine.publicKey, [{ audience: api, scopes: ["read"] }]),
				],
			},
			honestRelay,
		);
	}, readyWithinMs + 10_000);
	afterAll(() => core?.stop());

	const evidence = (assertion = machine.assertion(), proof = machine.proof()) => [
		{ form: "clientAssertion" as const, value: assertion },
		{ form: "dpopProof" as const, value: proof },
	];
	/** The client's bundle of a start, its one access token's texts as the Core's writer makes them. */
	const bundleFor = (flow: Flow, op: string, start: { id: string; acceptedAt: number }) => {
		const iat = Math.floor(start.acceptedAt / 1000);
		const token = {
			header: JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: "k13" }),
			claims: JSON.stringify({
				iss: provider.issuer,
				sub: machine.id,
				client_id: machine.id,
				o3co_subject_kind: "client",
				aud: api,
				scope: "read",
				iat,
				exp: iat + 300,
				jti: `jti-${op}`,
				cnf: { jkt: machine.jkt },
			}),
		};
		const input = tokens.digestInput(token.header, token.claims);
		if ("error" in input) throw new Error(input.error);
		return records.bundle(
			flow,
			op,
			{ start: start.id },
			[{ frame: "accessToken", digest: sha256(input.input) }],
			{
				via: "client",
				token,
			},
		);
	};

	it("K-13: the log refuses a stage after its op's abandonment, and a start using another's evidence element; the others are verified (ClientFlow023)", async () => {
		const flow = { of: "client", id: machine.id } as const;
		const startOf = (assertion?: string) => {
			const made = records.clientStart(flow, evidence(assertion), 1);
			if (made === undefined) throw new Error("no start");
			return made;
		};
		const first = machine.assertion();
		const w1 = startOf(first);
		const w2 = startOf();
		const s1 = await placed(core, flow, w1);
		const s2 = await placed(core, flow, w2);
		expect([s1.judged, s2.judged]).toEqual([verified, verified]);
		// (a) The first op abandoned; its bundle, not yet placed, is refused by the log.
		expect(
			(await placed(core, flow, records.abandonment(flow, w1.op, 1, sha256("k13-abandoned"))))
				.judged,
		).toEqual(verified);
		const beforeBundle = await core.writer.head(flow);
		expect(await place(core, flow, bundleFor(flow, w1.op, s1))).toEqual({ refused: "abandoned" });
		expect(await core.writer.head(flow)).toBe(beforeBundle);
		// U: the other op's bundle, no abandonment of it, verified.
		expect((await placed(core, flow, bundleFor(flow, w2.op, s2))).judged).toEqual(verified);
		// (b) Another op's start using the first's client assertion: refused by the log.
		const beforeStart = await core.writer.head(flow);
		expect(await place(core, flow, startOf(first))).toMatchObject({ refused: "evidenceUsed" });
		expect(await core.writer.head(flow)).toBe(beforeStart);
		// U: a start of its own evidence alone.
		expect((await placed(core, flow, startOf())).judged).toEqual(verified);
		// The client's flow does not stall: a new token, through an honest Front.
		const front = await core.world.front();
		const asked = await front.post(machine.request("read", api));
		const answered = await front.post(machine.request("read", api, asked.dpopNonce));
		expect(answered.status, JSON.stringify(answered.body)).toBe(200);
	});

	it("K-15: leaves no record forged but the bad writer's, none held or unjudged, on every flow it placed on (KP_04)", () =>
		expectSwept(core, { placed: 5, forged: 0, records: 7 }));
});
