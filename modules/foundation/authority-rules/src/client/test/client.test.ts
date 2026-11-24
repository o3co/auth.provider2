import { tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	context,
	coreRecord,
	digest,
	type FlowRecord,
	preimage,
	T0,
	checks as worldChecks,
} from "../../../test/fixtures/world.ts";
import { effectOf } from "../../chain/chain.ts";
import type { Checks } from "../../evidence/evidence.ts";
import { abandonedFamily, emptyState, type FlowEntry } from "../../fold/fold.ts";
import { judge, type Reading } from "../../judgment/judgment.ts";
import { type ClientAt, lifetimeMs, startOf, thumbprintOf, within } from "../client.ts";

// kernel-spec §6.1's client flow rules (V23) and V21's three bundle rows. A JWS of this world is
// `header.payload.kid`, verified where its kid is one of the keys' (`test/fixtures/world.ts`).

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const client = { of: "client", id: "svc" } as const;
const issuer = "https://core.example";
const keyOf = (kid: string, x: string) => ({ kty: "EC", crv: "P-256", x, y: `${x}y`, kid });
const written = keyOf("ck-1", "k1");
const other = keyOf("ck-2", "k2");
const jkt = thumbprintOf(written, digest) ?? "";
const at: ClientAt = { keys: [written] };
const startAt = T0 * 1000 + 1000;

/** A client's assertion and DPoP proof, each signed by `by`'s kid. */
const assertionBy = (by = written, over: Record<string, unknown> = {}, jti = "a1") =>
	`${b64({ alg: "ES256", typ: "JWT" })}.${b64({ iss: client.id, sub: client.id, aud: issuer, jti, iat: T0, exp: T0 + 60, ...over })}.${by.kid}`;
const proofBy = (by = written, jti = "p1", iat = T0) => {
	const { kid: _kid, ...jwk } = by;
	return `${b64({ alg: "ES256", typ: "dpop+jwt", jwk })}.${b64({ htm: "POST", htu: `${issuer}/oauth/token`, jti, iat })}.${by.kid}`;
};
const evidenceOf = (assertion = assertionBy(), proof = proofBy()) => [
	{ form: "clientAssertion" as const, value: assertion },
	{ form: "dpopProof" as const, value: proof },
];

const checks: Checks = {
	...worldChecks,
	selfCeiling: (id, version, audience, scope) =>
		id === client.id &&
		version === 3 &&
		audience === "https://api.example" &&
		scope.split(" ").every((s) => ["read", "write"].includes(s)),
};
const limits = { ...context().limits, evidenceWindow: 30_000 };

const start = (
	position: number,
	evidence = evidenceOf(),
	over: Partial<FlowRecord> = {},
	pre: Record<string, unknown> = {},
) => {
	const read = startOf(evidence, digest);
	if ("refused" in read) throw new Error(read.refused);
	return {
		record: coreRecord("start", position, {
			flow: client,
			op: read.op,
			last: false,
			registryVersion: 3,
			elements: [...read.elements],
			acceptedAt: startAt + (position - 1) * 1000,
			...over,
		} as Partial<FlowRecord>),
		preimage: preimage({ evidence, content: { via: "client" }, ...pre }),
	};
};

const tokenTexts = (claims: Record<string, unknown>) => ({
	header: JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: "t1" }),
	claims: JSON.stringify(claims),
});
const claimsAt = (acceptedAt: number, over: Record<string, unknown> = {}) => ({
	iss: issuer,
	sub: client.id,
	client_id: client.id,
	o3co_subject_kind: "client",
	aud: "https://api.example",
	scope: "read",
	iat: Math.floor(acceptedAt / 1000),
	exp: Math.floor(acceptedAt / 1000) + 300,
	jti: "t-1",
	cnf: { jkt },
	...over,
});
const tokenDigest = (texts: { header: string; claims: string }) => {
	const input = tokens.digestInput(texts.header, texts.claims);
	if ("error" in input) throw new Error(input.error);
	return digest(input.input);
};
const bundle = (
	position: number,
	of: { record: FlowRecord },
	claims: Record<string, unknown> = claimsAt(of.record.acceptedAt),
	over: Partial<FlowRecord> = {},
) => {
	const texts = tokenTexts(claims);
	return {
		record: coreRecord("bundle", position, {
			flow: client,
			op: of.record.op,
			stage: 2,
			tokens: [{ frame: "accessToken", digest: tokenDigest(texts) }],
			acceptedAt: of.record.acceptedAt + 500,
			...over,
		} as Partial<FlowRecord>),
		preimage: preimage({
			parent: of.record.id,
			evidence: [],
			content: { via: "client", token: texts },
		}),
	};
};

type Step = { record: FlowRecord; preimage: unknown };
const readingOf = (
	step: Step,
	prior: readonly FlowEntry[],
	over: Partial<Reading> = {},
): Reading => ({
	record: step.record,
	opening: { opened: step.preimage },
	keySets: { ever: ["mk-1"], atRecord: ["mk-1"] },
	versions: { registry: { at: 0 } },
	client: at,
	state: emptyState,
	prior,
	checks,
	context: { ...context(), limits },
	...over,
});
/** Judges each step on the entries before it, as the monitor does; the rulings in order. */
const judged = (steps: readonly Step[], over: Partial<Reading> = {}) => {
	const prior: FlowEntry[] = [];
	return steps.map((step) => {
		const ruling = judge(readingOf(step, prior, over));
		if ("wait" in ruling) throw new Error(ruling.wait);
		prior.push(ruling.entry);
		return ruling;
	});
};
const verdicts = (steps: readonly Step[], over: Partial<Reading> = {}) =>
	judged(steps, over).map((r) => ({
		row: r.row,
		verdict: r.entry.judgment.verdict,
		outcome: r.entry.judgment.outcome,
	}));
const ok = { row: "J13", verdict: "verified", outcome: "took" };
const forged = { row: "J7", verdict: "forged", outcome: "didNotTake" };
const held = { row: "J9", verdict: "held", outcome: "didNotTake" };

describe("a client's start's op id and elements (OpIdOf, Elems)", () => {
	it("are the digests of its evidence's signing inputs, whatever their order or signatures", () => {
		const read = startOf(evidenceOf(), digest);
		const swapped = startOf([...evidenceOf()].reverse(), digest);
		const [h, p] = assertionBy().split(".");
		const resigned = startOf(evidenceOf(`${h}.${p}.other`), digest);
		expect(swapped).toEqual(read);
		expect(resigned).toMatchObject({ op: (read as { op: string }).op });
		const inputs = evidenceOf().map((e) => e.value.split(".").slice(0, 2).join("."));
		expect(read).toMatchObject({
			op: `start:${digest(JSON.stringify({ assertion: inputs[0], proof: inputs[1] }))}`,
			elements: inputs.map((i) => digest(i)),
		});
		expect(startOf(evidenceOf(assertionBy(written, {}, "a2")), digest)).not.toMatchObject({
			op: (read as { op: string }).op,
		});
	});

	it("are refused for a form twice, a form it does not know, one missing, or a value no compact JWS", () => {
		const [a, p] = evidenceOf();
		for (const evidence of [
			[a, a, p],
			[a, p, p],
			[a],
			[p],
			[a, p, { form: "statement" as const, value: "x.y.z" }],
			[{ ...(a as { form: "clientAssertion"; value: string }), value: "not-a-jws" }, p],
		]) {
			expect(startOf(evidence as never, digest), JSON.stringify(evidence)).toHaveProperty(
				"refused",
			);
		}
	});
});

describe("a client's evidence's times, read before its bundle (KE-C02)", () => {
	it("hold an acceptance time within the window of each, as the rules' TimeOK reads them", () => {
		const at = T0 * 1000;
		expect(within(evidenceOf(), at, 30_000)).toBe(true);
		expect(within(evidenceOf(), at - 30_001, 30_000)).toBe(false);
		expect(within(evidenceOf(), (T0 + 60) * 1000 + 30_001, 30_000)).toBe(false);
		expect(within(evidenceOf(assertionBy(written, { iat: undefined })), at, 30_000)).toBe(true);
		const [a] = evidenceOf();
		expect(within(a ? [a] : [], at, 30_000)).toBe(false);
	});
});

describe("a client's start (J7, §6.1)", () => {
	it("is verified on its own flow, rooted in its client at the version it names, not asking J12's confirmation", () => {
		expect(verdicts([start(1)])).toEqual([ok]);
		const [ruling] = judged([start(1)]);
		expect(ruling?.entry).toMatchObject({ via: "client", client: { version: 3, key: jkt } });
		expect(ruling?.entry.changes).toEqual({});
	});

	it("is forged with an op id not its evidence's, elements not its evidence's, or naming none", () => {
		expect(verdicts([start(1, evidenceOf(), { op: "start:other" })])).toEqual([forged]);
		expect(verdicts([start(1, evidenceOf(), { elements: [digest("x"), digest("y")] })])).toEqual([
			forged,
		]);
		expect(verdicts([start(1, evidenceOf(), { elements: undefined })])).toEqual([forged]);
		expect(verdicts([start(1, evidenceOf(), { registryVersion: undefined })])).toEqual([forged]);
	});

	it("is forged where an element of its evidence was named by a start of the flow before, a recombination too", () => {
		const a2 = assertionBy(written, {}, "a2");
		const p2 = proofBy(written, "p2");
		const first = start(1);
		const second = start(2, evidenceOf(a2, p2));
		const recombined = start(3, evidenceOf(assertionBy(), p2));
		expect(verdicts([first, second, recombined])).toEqual([ok, ok, forged]);
	});

	it("is forged off its flow's client: another client's assertion, a key its version does not write, a proof by another key, no such client", () => {
		expect(verdicts([start(1, evidenceOf(assertionBy(written, { iss: "x", sub: "x" })))])).toEqual([
			forged,
		]);
		expect(verdicts([start(1, evidenceOf(assertionBy(other), proofBy(other)))])).toEqual([forged]);
		expect(verdicts([start(1, evidenceOf(assertionBy(), proofBy(other)))])).toEqual([forged]);
		const { kid: _kid, ...otherJwk } = other;
		const misnamed = `${b64({ alg: "ES256", typ: "dpop+jwt", jwk: otherJwk })}.${b64({ jti: "p9", iat: T0 })}.${written.kid}`;
		expect(verdicts([start(1, evidenceOf(assertionBy(), misnamed))])).toEqual([forged]);
		const { kid: _k, ...writtenJwk } = written;
		const untyped = `${b64({ alg: "ES256", typ: "JWT", jwk: writtenJwk })}.${b64({ jti: "p8", iat: T0 })}.${written.kid}`;
		expect(verdicts([start(1, evidenceOf(assertionBy(), untyped))])).toEqual([forged]);
		expect(verdicts([start(1)], { client: null })).toEqual([forged]);
		expect(verdicts([start(1, evidenceOf(), {}, { parent: "r-0" })])).toEqual([forged]);
	});

	it("is forged off a client's flow, as a code's or a refresh's start is on a client's", () => {
		const subject = { of: "subject", id: "sub-1" } as const;
		expect(verdicts([start(1, evidenceOf(), { flow: subject })])).toEqual([forged]);
		const code = start(1, evidenceOf(), {}, { parent: "r-0", content: { via: "code" } });
		expect(verdicts([code])).toEqual([forged]);
	});

	it("is held, unchecked, where the caller gives no client record or no evidence window", () => {
		expect(verdicts([start(1)], { client: undefined })).toEqual([held]);
		expect(verdicts([start(1)], { context: context() })).toEqual([held]);
	});

	it("took only with its evidence's times holding its acceptance, the window on each side", () => {
		const late = { acceptedAt: (T0 + 60) * 1000 + 30_001 };
		const early = { acceptedAt: T0 * 1000 - 30_001 };
		expect(verdicts([start(1, evidenceOf(), late)])).toEqual([{ ...ok, outcome: "didNotTake" }]);
		expect(verdicts([start(1, evidenceOf(), early)])).toEqual([{ ...ok, outcome: "didNotTake" }]);
		const unnamed = evidenceOf(assertionBy(written, { iat: undefined }));
		expect(verdicts([start(1, unnamed)])).toEqual([ok]);
		const edge = { acceptedAt: T0 * 1000 + 30_000 };
		expect(verdicts([start(1, evidenceOf(), edge)])).toEqual([ok]);
	});
});

describe("a client's bundle (J7, §6.1 and V21's rows)", () => {
	it("is verified for one access token of its client, within its own ceiling, bound to its start's key", () => {
		const s = start(1);
		expect(verdicts([s, bundle(2, s)])).toEqual([ok, ok]);
		const [, ruling] = judged([s, bundle(2, s)]);
		expect(ruling?.entry.changes).toEqual({});
		expect(abandonedFamily(ruling?.entry ?? ({} as FlowEntry))).toBeUndefined();
	});

	it("is forged for another token or digest, another subject or client, a person's authentication", () => {
		const s = start(1);
		const at0 = s.record.acceptedAt;
		const two = bundle(2, s);
		const twice = {
			...two,
			record: {
				...two.record,
				tokens: [...(two.record.tokens ?? []), { frame: "family", digest: digest("f") }],
			} as FlowRecord,
		};
		const digestOff = {
			...two,
			record: {
				...two.record,
				tokens: [{ frame: "accessToken", digest: digest("x") }],
			} as FlowRecord,
		};
		for (const b of [
			twice,
			digestOff,
			bundle(2, s, claimsAt(at0, { sub: "x" })),
			bundle(2, s, claimsAt(at0, { client_id: "x" })),
			bundle(2, s, claimsAt(at0, { amr: ["pwd"] })),
			bundle(2, s, claimsAt(at0, { aud: ["https://api.example", "https://b.example"] })),
		]) {
			expect(verdicts([s, b])).toEqual([ok, forged]);
		}
	});

	it("is forged outside its client's own ceiling, the issuer among them, or past fifteen minutes of its start", () => {
		const s = start(1);
		const at0 = s.record.acceptedAt;
		const iat = Math.floor(at0 / 1000);
		for (const claims of [
			claimsAt(at0, { scope: "admin" }),
			claimsAt(at0, { scope: undefined }),
			claimsAt(at0, { aud: issuer }),
			claimsAt(at0, { exp: iat + lifetimeMs / 1000 + 1 }),
			claimsAt(at0, { iat: iat + 1 }),
			claimsAt(at0, { cnf: { jkt: "other" } }),
		]) {
			expect(verdicts([s, bundle(2, s, claims)]), JSON.stringify(claims)).toEqual([ok, forged]);
		}
		expect(
			verdicts([s, bundle(2, s, claimsAt(at0, { exp: Math.floor((at0 + lifetimeMs) / 1000) }))]),
		).toEqual([ok, ok]);
	});

	it("is forged after its start did not take, and naming a root", () => {
		const late = start(1, evidenceOf(), { acceptedAt: (T0 + 120) * 1000 });
		expect(verdicts([late, bundle(2, late)])).toEqual([{ ...ok, outcome: "didNotTake" }, forged]);
		const s = start(1);
		const rooted = bundle(2, s);
		const named = { ...rooted, preimage: { ...(rooted.preimage as object), root: "r-0" } };
		expect(verdicts([s, named])).toEqual([ok, forged]);
	});

	it("is held, unchecked, with no self ceiling given, and inherits its unchecked start's hold", () => {
		const s = start(1);
		const { selfCeiling: _none, ...without } = checks;
		expect(verdicts([s, bundle(2, s)], { checks: without })).toEqual([ok, held]);
		expect(verdicts([s, bundle(2, s)], { client: undefined })).toEqual([held, held]);
	});

	it("changes nothing, its abandonment dropping no family", () => {
		const s = start(1);
		const b = bundle(2, s);
		const [, ruling] = judged([s, b]);
		const abandon = coreRecord("abandonment", 3, {
			flow: client,
			op: `abandonment:1:${s.record.op}`,
			abandons: { op: s.record.op, attempt: 1, digest: digest("p") },
		} as Partial<FlowRecord>);
		const changes = effectOf({
			record: abandon,
			preimage: preimage({}),
			state: emptyState,
			prior: ruling ? [ruling.entry] : [],
			checks,
			context: context(),
		});
		expect(changes).toEqual({});
	});
});
