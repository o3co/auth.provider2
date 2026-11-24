import { createHash } from "node:crypto";
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
const evidence = [{ form: "dpopProof" as const, value: "proof" }];
const ask: BundleAsk = {
	request: { grant, grantType: "client_credentials" },
	limits: {},
	evidence,
	nth: 0,
};
const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
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
		expect(world.book.sent[0]?.stage.preimage).toEqual({ v: 1, evidence, content: {} });
		expect(world.book.sent[1]?.stage.preimage).toMatchObject({ parent: start?.id, evidence: [] });
	});

	it("names its op after the request's evidence and its place in the request, and names its root's reference", async () => {
		const issue = world.run(await world.replica("w1"));
		await issue({ ...ask, root: "registry-7" });
		await issue({ ...ask, nth: 1 });
		const ops = records().map((r) => r.op);
		expect(ops[0]).toBe(`start:${sha256(JSON.stringify([evidence, 0]))}`);
		expect(ops[2]).toBe(`start:${sha256(JSON.stringify([evidence, 1]))}`);
		expect(world.book.sent[0]?.stage.preimage).toMatchObject({ root: "registry-7" });
		expect(
			evidenceOf({ headers: new Map([["dpop", "p"]]), fields: { single: () => "a" } } as never),
		).toEqual([
			{ form: "dpopProof", value: "p" },
			{ form: "clientAssertion", value: "a" },
		]);
	});

	it("signs nothing when its append is refused, its op closed", async () => {
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
		expect(world.frames.value({ flow, op: records()[0]?.op } as never)).toMatchObject({
			intent: { state: "closed" },
		});
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
		await expect(issue({ ...ask, nth: 1 })).rejects.toSatisfy(isUnavailable);
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
		expect(world.frames.value({ flow, op: records()[0]?.op } as never)).toMatchObject({
			intent: { state: "closed" },
		});
	});
});
