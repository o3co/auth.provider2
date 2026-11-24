import { createHash } from "node:crypto";
import { clientRules } from "@mod/authority-rules";
import { assemble, defineModule, isUnavailable, kernelConfig, Unavailable } from "@mod/kernel";
import type { AccessGrant, Issued, PreparedAccess } from "@mod/tokens";
import {
	frameStore,
	operationKinds,
	stateOwners,
	type TransparencyLog,
	transparency,
	transparencyLog,
} from "@mod/transparency";
import transparencyModule from "@mod/transparency/module";
import { logBook, memoryFrames } from "@mod/transparency/testing";
import { type AppendAnswer, opIds, tokens as receipts } from "@mod/transparency-wire";
import { beforeEach, describe, expect, it } from "vitest";
import { type BundleAsk, bundleKind, bundling, evidenceOf } from "../bundle.ts";

const now = 1_800_000_000_000;
const grant: AccessGrant = {
	subject: "svc",
	subjectKind: "client",
	issuedTo: "svc",
	audience: ["https://api"],
	scope: ["read"],
};
const flow = { of: "client", id: "svc" } as const;
const T = now / 1000;
/** A claims text of a JWT id, issued at `iat` (seconds), for a minute. */
const claimed = (jti: string, iat = T) => JSON.stringify({ jti, iat, exp: iat + 60 });
const jws = (payload: string, signature = "c2ln") =>
	`${Buffer.from('{"alg":"ES256"}').toString("base64url")}.${Buffer.from(payload).toString("base64url")}.${signature}`;
const evidence = [
	{ form: "clientAssertion" as const, value: jws(claimed("a1")) },
	{ form: "dpopProof" as const, value: jws(claimed("p1")) },
];
const ask: BundleAsk = {
	request: { grant, grantType: "client_credentials" },
	limits: {},
	evidence,
	version: 3,
};
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const started = (e: BundleAsk["evidence"]) => {
	const read = clientRules.start(e, sha256);
	if ("refused" in read) throw new Error(read.refused);
	return read;
};
const issued: Issued = {
	kind: "issued",
	access: { token: "h.c.s", id: "j", expiresAt: now + 300_000, expiresIn: 300, tokenType: "DPoP" },
};
const expired = {
	kind: "refused",
	policy: "tokens",
	reason: "no_lifetime_left",
	description: "expired",
} as const;

let world: Awaited<ReturnType<typeof makeWorld>>;
async function makeWorld(wrap: (log: TransparencyLog) => TransparencyLog = (l) => l) {
	const frames = memoryFrames(["state"]);
	const book = logBook(() => now);
	const replica = async (instance: string) => {
		const app = await assemble({
			modules: [
				transparencyModule,
				defineModule({ name: "in-memory", replicaSafe: true, takes: [] }, (m) => [
					m.provide(frameStore).by(() => frames.frames),
					m.provide(transparencyLog).by(() => wrap(book.as(instance))),
					m.contribute(stateOwners).by(() => ({
						name: "every-field",
						holds: ["keyGeneration", "keys", "approvals", "families", "consumed"],
						parts: ["state"],
						records: () => [{ part: "state", name: "state" }],
						read: () => ({}),
						write: () => [undefined],
					})),
					m.contribute(operationKinds).by(() => bundleKind),
				]),
			],
			config: kernelConfig(),
		});
		return app.get(transparency);
	};
	const signs: (() => Promise<Issued>)[] = [];
	const prepared: { acceptedAt?: number }[] = [];
	const run = (t: Awaited<ReturnType<typeof replica>>) =>
		bundling({
			transparency: t,
			digest: (preimage) => book.as("w1").digest(preimage),
			issuance: {
				admits: async () => ({ kind: "allowed" }),
				prepare: async (_request, limits) => {
					prepared.push({
						...(limits?.acceptedAt === undefined ? {} : { acceptedAt: limits.acceptedAt }),
					});
					return Object.freeze({
						kind: "prepared",
						headerText: '{"alg":"ES256"}',
						claimsText: JSON.stringify({ iat: Math.floor((limits?.acceptedAt ?? 0) / 1000) }),
					}) as PreparedAccess;
				},
				sign: async () => (signs.shift() ?? (async () => issued))(),
			},
			fresh: () => "fresh",
			pause: async () => {},
			looks: 3,
		});
	return { frames, book, replica, run, signs, prepared };
}
beforeEach(async () => {
	world = await makeWorld();
	world.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
});
const records = () => world.book.records(flow).map((p) => p.record);
/** Whether the op's intent is closed: its frame says so, or is gone with its end. */
const closed = (op: string | undefined) => {
	const frame = world.frames.value({ flow, op } as never) as
		| { intent: { state: string } | null }
		| undefined;
	return frame === undefined || frame.intent?.state === "closed";
};

describe("a bundle, owned by the token endpoint (A40)", () => {
	it("records its start with the request's evidence, then its token's digest once, under the start, on the client's own flow", async () => {
		const issue = world.run(await world.replica("w1"));
		expect(await issue(ask)).toEqual(issued);
		const [start, bundle] = records();
		expect(start).toMatchObject({ kind: "start", flow, stage: 1, last: false });
		expect(bundle).toMatchObject({ kind: "bundle", flow, op: start?.op, stage: 2, last: true });
		const input = receipts.digestInput(
			'{"alg":"ES256"}',
			JSON.stringify({ iat: Math.floor(now / 1000) }),
		);
		if ("error" in input) throw new Error(input.error);
		expect(bundle?.tokens).toEqual([{ frame: "accessToken", digest: sha256(input.input) }]);
		// The token's issue time is the start's acceptance time; no append names a previous position.
		expect(world.prepared).toEqual([{ acceptedAt: start?.acceptedAt }]);
		expect(world.book.sent.map((s) => "prev" in s)).toEqual([false, false]);
		expect(world.book.sent[0]?.stage).toMatchObject({
			registryVersion: 3,
			elements: started(evidence).elements,
			preimage: { v: 1, evidence, content: { via: "client" } },
		});
		// The bundle carries the token's texts, which the rules read its claims from.
		expect(world.book.sent[1]?.stage.preimage).toEqual({
			v: 1,
			parent: start?.id,
			evidence: [],
			content: {
				via: "client",
				token: {
					header: '{"alg":"ES256"}',
					claims: JSON.stringify({ iat: Math.floor(now / 1000) }),
				},
			},
		});
	});

	it("names a client's op after its evidence's fixed shape, whatever its order or signatures, never a fresh ground", async () => {
		const issue = world.run(await world.replica("w1"));
		await issue(ask);
		const op = records()[0]?.op;
		expect(op).toBe(started(evidence).op);
		const [a, p] = evidence;
		if (!a || !p) throw new Error("no evidence");
		const resigned = [{ ...a, value: jws(claimed("a1"), "b3RoZXI") }, p];
		expect(started([p, a]).op).toBe(op);
		expect(started(resigned).op).toBe(op);
	});

	it("refuses before deciding a client's own token lacking its assertion, its proof or its registry version, or carrying one twice, recording nothing", async () => {
		const issue = world.run(await world.replica("w1"));
		const [a, p] = evidence;
		if (!a || !p) throw new Error("no evidence");
		for (const lacking of [[a], [p], [], [a, p, p]]) {
			expect(await issue({ ...ask, evidence: lacking })).toMatchObject({
				kind: "refused",
				policy: "token-endpoint",
				reason: "evidence",
			});
		}
		const { version: _none, ...unversioned } = ask;
		expect(await issue(unversioned)).toMatchObject({ kind: "refused", reason: "evidence" });
		expect(world.book.sent).toEqual([]);
	});

	it("sends no bundle after a start its evidence's times may not have taken, closing its op (KE-C02)", async () => {
		const issue = world.run(await world.replica("w1"));
		const stale = [
			{ form: "clientAssertion" as const, value: jws(claimed("a9", T - 3600)) },
			{ form: "dpopProof" as const, value: jws(claimed("p9", T - 3600)) },
		];
		let signed = 0;
		world.signs.push(async () => {
			signed++;
			return issued;
		});
		await expect(issue({ ...ask, evidence: stale })).rejects.toSatisfy(isUnavailable);
		expect([records().map((r) => r.kind), signed]).toEqual([["start"], 0]);
		expect(closed(records()[0]?.op)).toBe(true);
	});

	it("refuses a client whose evidence its flow used, as for good, leaving its op to its lease's end", async () => {
		world = await makeWorld((log) => ({
			...log,
			append: async (stage, prev) =>
				stage.kind === "start"
					? ({ v: 1, result: "refused", refusal: "evidenceUsed" } satisfies AppendAnswer)
					: log.append(stage, prev),
		}));
		const issue = world.run(await world.replica("w1"));
		expect(await issue(ask)).toMatchObject({ kind: "refused", reason: "evidence_used" });
		const frame = world.frames.value({ flow, op: started(evidence).op } as never) as {
			intent: { state: string };
		};
		expect(frame.intent.state).toBe("pending");
	});

	it("names a person's op after the evidence verified, and names its root's reference", async () => {
		const issue = world.run(await world.replica("w1"));
		const person = { ...grant, subject: "alice", subjectKind: "user" as const };
		await issue({ ...ask, request: { ...ask.request, grant: person }, root: "approval-7" });
		const subject = { of: "subject", id: "alice" } as const;
		const [start] = world.book.records(subject).map((p) => p.record);
		expect(start?.op).toBe(`start:${sha256(JSON.stringify(evidence))}`);
		expect(world.book.sent[0]?.stage.preimage).toMatchObject({ root: "approval-7", content: {} });
		// Evidence is what was verified: the DPoP proof of a DPoP binding, the assertion of an authentication that verified one.
		const request = { headers: new Map([["dpop", "p"]]), fields: { single: () => "a" } } as never;
		const dpop = { member: "jkt", confirmation: "t", tokenType: "DPoP" };
		expect(evidenceOf(request, { binding: dpop, assertion: true })).toEqual([
			{ form: "dpopProof", value: "p" },
			{ form: "clientAssertion", value: "a" },
		]);
		const bearer = { member: "x5t#S256", confirmation: "t", tokenType: "Bearer" };
		expect(evidenceOf(request, { binding: bearer, assertion: false })).toEqual([]);
		expect(evidenceOf(request, { assertion: false })).toEqual([]);
	});

	it("signs nothing when its append is refused, its op left to its lease's end but on abandoned", async () => {
		world = await makeWorld((log) => ({
			...log,
			append: async (stage, prev) =>
				stage.kind === "bundle"
					? ({ v: 1, result: "refused", refusal: "lateBundle" } satisfies AppendAnswer)
					: log.append(stage, prev),
		}));
		let signed = 0;
		world.signs.push(async () => {
			signed++;
			return issued;
		});
		const issue = world.run(await world.replica("w1"));
		await expect(issue(ask)).rejects.toSatisfy(isUnavailable);
		expect(signed).toBe(0);
		expect(closed(records()[0]?.op)).toBe(false);
		world = await makeWorld((log) => ({
			...log,
			append: async (stage, prev) =>
				stage.kind === "bundle"
					? ({ v: 1, result: "refused", refusal: "abandoned" } satisfies AppendAnswer)
					: log.append(stage, prev),
		}));
		world.book.judgeOnAppend({ verdict: "verified", outcome: "took" });
		await expect(world.run(await world.replica("w1"))(ask)).rejects.toSatisfy(isUnavailable);
		expect(closed(records()[0]?.op)).toBe(true);
	});

	it("signs nothing when its append's answer is lost, leaving its op to be abandoned", async () => {
		world = await makeWorld((log) => ({
			...log,
			append: async (stage, prev) => {
				const answer = await log.append(stage, prev);
				if (stage.kind === "bundle") throw new Unavailable("log");
				return answer;
			},
		}));
		let signed = 0;
		world.signs.push(async () => {
			signed++;
			return issued;
		});
		await expect(world.run(await world.replica("w1"))(ask)).rejects.toSatisfy(isUnavailable);
		expect(signed).toBe(0);
		expect(records().map((r) => r.kind)).toEqual(["start", "bundle"]);
	});

	it("appends the same bundle again, the same id and bytes, and signs again where signing fell after the receipts", async () => {
		world.signs.push(async () => {
			throw new Unavailable("keys");
		});
		expect(await world.run(await world.replica("w1"))(ask)).toEqual(issued);
		const bundles = world.book.sent.filter((s) => s.stage.kind === "bundle");
		expect(bundles).toHaveLength(2);
		expect(bundles[1]?.stage).toEqual(bundles[0]?.stage);
		expect(records().map((r) => r.kind)).toEqual(["start", "bundle"]);
	});

	it("hands nothing out on a refusal after its receipts: the bundle, left alone, is abandoned by another replica", async () => {
		world.signs.push(async () => expired);
		expect(await world.run(await world.replica("w1"))(ask)).toEqual(expired);
		const op = records()[0]?.op ?? "";
		world.frames.clock.set(5000);
		await (await world.replica("w2")).tend(flow);
		expect(records().at(-1)).toMatchObject({
			kind: "abandonment",
			op: opIds.abandonment(op, 1),
		});
	});

	it("answers no token unless its bundle is taken in as its owner's took", async () => {
		world.book.judgeOnAppend(undefined);
		const issue = world.run(await world.replica("w1"));
		await expect(issue(ask)).rejects.toSatisfy(isUnavailable);
		world.book.judgeOnAppend({ verdict: "held", outcome: "took" });
		const other = [
			{ form: "clientAssertion" as const, value: jws(claimed("a2")) },
			{ form: "dpopProof" as const, value: jws(claimed("p2")) },
		];
		await expect(issue({ ...ask, evidence: other })).rejects.toSatisfy(isUnavailable);
	});

	it("records nothing for an issuance the policies refuse, and closes its op on a refusal once its start is recorded", async () => {
		const refused = { kind: "refused", policy: "p", reason: "r", description: "d" } as const;
		const t = await world.replica("w1");
		const base = {
			transparency: t,
			digest: () => "d".repeat(43),
			fresh: () => "f",
			pause: async () => {},
			looks: 1,
		};
		const sign = async () => issued;
		const refusing = bundling({
			...base,
			issuance: { admits: async () => refused, prepare: async () => refused, sign },
		});
		expect(await refusing(ask)).toEqual(refused);
		expect(records()).toEqual([]);
		const late = bundling({
			...base,
			issuance: { admits: async () => ({ kind: "allowed" }), prepare: async () => refused, sign },
		});
		expect(await late(ask)).toEqual(refused);
		expect(records().map((r) => r.kind)).toEqual(["start"]);
		expect(closed(records()[0]?.op)).toBe(true);
	});
});
