import { continuations } from "@mod/continuation-wire";
import { canonicalText } from "@mod/sdk-core-wire";
import { tokens as tokenWire } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import {
	allowed,
	type Checks,
	emptyState,
	type FlowEntry,
	judge,
	type Reading,
	tokenRules,
} from "../src/contract.ts";
import { type Continued, coreRecords, type Written } from "../src/testing.ts";
import {
	added,
	addParts,
	approval,
	askOf,
	codeBundle,
	codeStart,
	deletion,
	firstKey,
	firstKeyEvidence,
	login,
	newKey,
	prefixOf,
	refreshBundle,
	refreshStart,
	reservation,
	type Step,
	signedUp,
	signUpParts,
} from "./fixtures/flow.ts";
import {
	assertion,
	context,
	coreRecord,
	digest,
	esig,
	passkeyManage,
	screen,
	sign,
	subject,
	T0,
	checks as worldChecks,
} from "./fixtures/world.ts";

// The records `./testing` makes from evidence given are the ones the owner's fixtures and the Core's
// writers make, which the rules take; each with one thing changed, the rules refuse it.

const records = coreRecords(digest);
const flow = subject;

/** A record made here, placed at `position` as the fixtures place one. */
const placed = (w: Written, position: number): Step => {
	const { preimage, ...named } = w;
	return { record: coreRecord(w.kind, position, named), preimage };
};
/** What a writer names, apart from what the log adds on placing it. */
const fieldsOf = (step: Step) => {
	const r = step.record as Omit<Written, "preimage">;
	const { kind, op, stage, last, keyChange, approval, tokens, elements, registryVersion } = r;
	return { kind, op, stage, last, keyChange, approval, tokens, elements, registryVersion };
};
/** The same record in all a writer makes: its fields and its preimage. */
const same = (made: Step, expected: Step) => {
	expect(fieldsOf(made)).toEqual(fieldsOf(expected));
	expect(made.preimage).toEqual(expected.preimage);
};
/** The rules' answer on the flow the steps before it make. */
const on = (step: Step, before: Step[] = []) => {
	const p = prefixOf(before);
	return allowed(askOf(step, p.state, p.prior));
};
const ok = { allowed: true };

const signed = (stage: "register" | "delete", statement: string, body: string): Continued => ({
	seq: 1,
	body,
	signature: esig(screen.e_sig, continuations.of(stage, digest(statement), 1, digest(body))),
});
const ceremonyOf = (creationJws: string, possessionJws: string, key = newKey) => ({
	creation: creationJws,
	continuation: signed("register", creationJws, JSON.stringify(key)),
	possession: possessionJws,
	assertion: assertion(key, possessionJws),
	...key,
});
const otherKey = { ...screen.e_sig, x: "b3RoZXI" };

describe("a person's key changes", () => {
	it("makes the first key and a sign-up's key the fixtures make, which the rules take on an empty flow", () => {
		const { creationJws, possessionJws } = firstKeyEvidence;
		const made = placed(
			records.firstKey(flow, reservation, ceremonyOf(creationJws, possessionJws)),
			1,
		);
		same(made, firstKey(1));
		expect(on(made)).toEqual(ok);

		const parts = signUpParts();
		const ceremony = ceremonyOf(parts.creation, parts.possession);
		const up = placed(records.firstKey(flow, parts.reservation, ceremony, parts.t), 1);
		same(up, signedUp(1, parts));
		expect(on(up)).toEqual(ok);
		// Under another reservation than its possession names (P 355).
		expect(on(placed(records.firstKey(flow, "res-other", ceremony, parts.t), 1))).toEqual({
			allowed: false,
			reason: "the possession is for another reservation than the op",
		});
	});

	it("makes a key added and a key deleted as the fixtures make them, and refuses each with one thing changed", () => {
		const parts = addParts();
		const by = { registration: "r-1", statement: parts.statement, assertion: parts.asserted };
		const ceremony = ceremonyOf(parts.creation, parts.possession, parts.key);
		const add = placed(records.addedKey(flow, parts.reservation, by, ceremony), 2);
		same(add, added(2, "r-1", parts));
		expect(on(add, [firstKey(1)])).toEqual(ok);
		// Approved by a key the flow does not hold.
		const unheld = placed(
			records.addedKey(flow, parts.reservation, { ...by, registration: "r-9" }, ceremony),
			2,
		);
		expect(on(unheld, [firstKey(1)])).toEqual({
			allowed: false,
			reason: "the approving key is not live on the flow",
		});

		const statement = sign(passkeyManage("del-1"), "ring-1");
		const body = canonicalText({ credential_id: parts.key.credential });
		const manage = { registration: "r-1", statement, assertion: assertion(newKey, statement) };
		const two = [firstKey(1), added(2, "r-1", parts)];
		const del = placed(
			records.deletedKey(
				flow,
				"del-3",
				manage,
				signed("delete", statement, body),
				parts.key.credential,
			),
			3,
		);
		same(del, deletion(3, "r-1", parts.key.credential));
		expect(on(del, two)).toEqual(ok);
		// Its continuation signed by another key than the screen's E_sig.
		const forged = {
			...signed("delete", statement, body),
			signature: esig(otherKey, continuations.of("delete", digest(statement), 1, digest(body))),
		};
		const resigned = placed(
			records.deletedKey(flow, "del-3", manage, forged, parts.key.credential),
			3,
		);
		expect(on(resigned, two)).toEqual({
			allowed: false,
			reason: "the continuation is not the screen's over the passkey-manage",
		});
	});
});

describe("an approval and the tokens rooted in it", () => {
	const fixture = approval(2, "r-1");
	const [t, a] = (fixture.preimage.evidence as { value: string }[]).map((e) => e.value);
	const by = { registration: "r-1", statement: t ?? "", assertion: a ?? "" };
	const made = placed(records.approval(flow, "op-2", by, digest("code-sid-1")), 2);
	const code = { via: "code", code: digest("code-sid-1"), client: "rp" } as const;
	const frames = [
		{ frame: "accessToken", digest: "a".repeat(43) },
		{ frame: "family", digest: "f".repeat(43) },
	] as const;

	it("makes the approval the fixtures make, which the rules take on a live key and refuse on another", () => {
		same(made, fixture);
		expect(on(made, [firstKey(1)])).toEqual(ok);
		const unheld = placed(
			records.approval(flow, "op-2", { ...by, registration: "r-9" }, digest("code-sid-1")),
			2,
		);
		expect(on(unheld, [firstKey(1)])).toEqual({
			allowed: false,
			reason: "the assertion's key is not live on the flow",
		});
	});

	it("makes a code's start as the Core's writer does, rooted in its approval and its parent, and its bundle", () => {
		const start = placed(records.start(flow, "login", "r-2", code), 3);
		// The fixture's start names its parent alone; the Core's writer names its root too.
		const expected = codeStart(3, "login", "r-2");
		same(start, { ...expected, preimage: { ...expected.preimage, root: "r-2" } });
		expect(on(start, [firstKey(1), made])).toEqual(ok);
		const otherCode = placed(records.start(flow, "login", "r-2", { ...code, client: "rp-2" }), 3);
		expect(on(otherCode, [firstKey(1), made])).toEqual({
			allowed: false,
			reason: "the start names another code or client than its approval",
		});

		const bundle = placed(
			records.bundle(flow, "login", { start: "r-3", root: "r-2" }, [...frames], { via: "code" }),
			4,
		);
		same(bundle, codeBundle(4, "login", "r-3", "r-2"));
		expect(on(bundle, [firstKey(1), made, start])).toEqual(ok);
		const unrooted = placed(
			records.bundle(flow, "login", { start: "r-3", root: "r-9" }, [...frames], { via: "code" }),
			4,
		);
		expect(on(unrooted, [firstKey(1), made, start])).toEqual({
			allowed: false,
			reason: "the bundle roots elsewhere than its start",
		});
	});

	it("makes a refresh's start and bundle on a family, and refuses a start at another rotation", () => {
		const refresh = { via: "refresh", rotation: 0 } as const;
		const start = placed(records.start(flow, "rf-1", "r-4", refresh), 5);
		const expected = refreshStart(5, "rf-1", "r-4");
		same(start, { ...expected, preimage: { ...expected.preimage, root: "r-4" } });
		expect(on(start, login())).toEqual(ok);
		const rotated = placed(records.start(flow, "rf-1", "r-4", { ...refresh, rotation: 1 }), 5);
		expect(on(rotated, login())).toEqual({
			allowed: false,
			reason: "the refresh is of another rotation",
		});

		const bundle = placed(
			records.bundle(flow, "rf-1", { start: "r-5", root: "r-4" }, [...frames], refresh),
			6,
		);
		same(bundle, refreshBundle(6, "rf-1", "r-5", "r-4"));
		expect(on(bundle, [...login(), start])).toEqual(ok);
	});
});

describe("a client's own token", () => {
	// A client of this world (`src/client/test/client.test.ts`'s): its key written at registry version 3.
	const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const client = { of: "client", id: "svc" } as const;
	const issuer = "https://core.example";
	const written = { kty: "EC", crv: "P-256", x: "k1", y: "k1y", kid: "ck-1" };
	const { kid: _kid, ...jwk } = written;
	const proofOf = (jti: string) => ({
		form: "dpopProof" as const,
		value: `${b64({ alg: "ES256", typ: "dpop+jwt", jwk })}.${b64({ htm: "POST", htu: `${issuer}/oauth/token`, jti, iat: T0 })}.ck-1`,
	});
	const evidence = (jti = "a1") => [
		{
			form: "clientAssertion" as const,
			value: `${b64({ alg: "ES256", typ: "JWT" })}.${b64({ iss: client.id, sub: client.id, aud: issuer, jti, iat: T0, exp: T0 + 60 })}.ck-1`,
		},
		proofOf("p1"),
	];
	const checks: Checks = {
		...worldChecks,
		selfCeiling: (id, version, audience, scope) =>
			id === client.id && version === 3 && audience === "https://api.example" && scope === "read",
	};
	const limits = { ...context().limits, evidenceWindow: 30_000 };
	/** Each step judged on the entries before it, as the monitor does: the entries. */
	const judgedEntries = (steps: readonly Step[]) => {
		const prior: FlowEntry[] = [];
		for (const step of steps) {
			const reading: Reading = {
				record: step.record,
				opening: { opened: step.preimage },
				keySets: { ever: ["mk-1"], atRecord: ["mk-1"] },
				versions: { registry: { at: 0 } },
				client: { keys: [written] },
				state: emptyState,
				prior,
				checks,
				context: { ...context(), limits },
			};
			const ruling = judge(reading);
			if ("wait" in ruling) throw new Error(ruling.wait);
			prior.push(ruling.entry);
		}
		return prior;
	};
	const judged = (steps: readonly Step[]) =>
		judgedEntries(steps).map((e) => ({ verdict: e.judgment.verdict, outcome: e.judgment.outcome }));
	const tokenOf = (acceptedAt: number) => {
		const iat = Math.floor(acceptedAt / 1000);
		const texts = {
			header: JSON.stringify({ alg: "ES256", typ: "at+jwt", kid: "t1" }),
			claims: JSON.stringify({
				iss: issuer,
				sub: client.id,
				client_id: client.id,
				o3co_subject_kind: "client",
				aud: "https://api.example",
				scope: "read",
				iat,
				exp: iat + 300,
				jti: "t-1",
				cnf: { jkt: jktOf() },
			}),
		};
		const input = tokenWire.digestInput(texts.header, texts.claims);
		if ("error" in input) throw new Error(input.error);
		return { texts, digest: digest(input.input) };
	};
	const jktOf = () => digest(canonicalText({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));

	it("derives a client's start's op and elements as the rules do, which the monitor verifies with its bundle", () => {
		const made = records.clientStart(client, evidence(), 3);
		if (made === undefined) throw new Error("no start");
		const of = tokenRules.client.start(evidence(), digest);
		if ("refused" in of) throw new Error(of.refused);
		expect(made).toMatchObject({ op: of.op, elements: of.elements, registryVersion: 3 });
		expect(made.preimage).toEqual({ v: 1, evidence: evidence(), content: { via: "client" } });
		const start = placed(made, 1);
		const { texts, digest: tokenDigest } = tokenOf(start.record.acceptedAt);
		const tokens = [{ frame: "accessToken" as const, digest: tokenDigest }];
		const bundle = placed(
			records.bundle(client, of.op, { start: start.record.id }, tokens, {
				via: "client",
				token: texts,
			}),
			2,
		);
		const verified = { verdict: "verified", outcome: "took" };
		expect(judged([start, bundle])).toEqual([verified, verified]);
		// Another op's start using an element of the first's evidence (its client assertion).
		const reused = records.clientStart(client, [...evidence().slice(0, 1), proofOf("p2")], 3);
		if (reused === undefined) throw new Error("no start");
		expect(reused.op).not.toBe(made.op);
		const p = prefixOf([]);
		const first = judgedEntries([start]);
		expect(
			allowed({ ...askOf(placed(reused, 2), p.state, first), client: { keys: [written] }, checks }),
		).toEqual({
			allowed: false,
			reason: "an evidence element is used on the flow",
		});
		expect(records.clientStart(client, evidence().slice(0, 1), 3)).toBeUndefined();
	});
});

describe("an abandonment", () => {
	it("makes the fixtures' abandonment of an op, which the rules take, its family dropped", () => {
		const made = placed(records.abandonment(flow, "login", 1, "p".repeat(43)), 5);
		expect(fieldsOf(made)).toEqual(
			fieldsOf({
				record: coreRecord("abandonment", 5, {
					op: "abandonment:1:login",
					abandons: { op: "login", attempt: 1, digest: "p".repeat(43) },
				}),
				preimage: {},
			}),
		);
		expect((made.record as { abandons?: unknown }).abandons).toEqual({
			op: "login",
			attempt: 1,
			digest: "p".repeat(43),
		});
		expect(made.preimage).toEqual({ v: 1, evidence: [], content: {} });
		const before = prefixOf(login());
		expect(Object.keys(before.state.families)).toEqual(["r-4"]);
		expect(on(made, login())).toEqual(ok);
		expect(prefixOf([...login(), made]).state.families).toEqual({});
	});
});
