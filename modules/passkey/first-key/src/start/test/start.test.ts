import { randomBytes } from "node:crypto";
import type { Keys } from "@mod/keys";
import { firstKey, hpke } from "@mod/sdk-core-wire";
import type { Verified } from "@mod/users";
import { describe, expect, it } from "vitest";
import { memoryKept } from "../../../test/fixtures/kept.ts";
import { screenPoints } from "../../../test/fixtures/screen.ts";
import type { EvidenceAnswer, FirstKeyEvidence, StoredNonce } from "../../contract.ts";
import { dispatchOver } from "../../dispatch/dispatch.ts";
import { evidenceOver } from "../../evidence/evidence.ts";
import type { Issued, Passed } from "../../issuing/issuing.ts";
import { noncesOver } from "../../nonces/nonces.ts";
import type { SealedRequest } from "../../sealed/sealed.ts";
import { type Ended, startOver } from "../../start/start.ts";

const bytes = (n: number, fill: number) => new Uint8Array(n).fill(fill);

/** A start's world: its stores in memory, the Core's keys and a kind of evidence as stand-ins. */
async function world(
	p: {
		answer?: EvidenceAnswer["kind"] | "throws";
		issued?: Issued | "throws";
		opens?: unknown;
		started?: boolean;
		max?: number;
		sealFails?: boolean;
	} = {},
) {
	const nonces = noncesOver({
		store: memoryKept<StoredNonce>().store,
		random: (n) => randomBytes(n),
		lifetimeMs: 120_000,
	});
	const sealedTo: { info: string; aad: string; plain: string }[] = [];
	const keys: Pick<Keys, "open" | "seal"> = {
		open: async () =>
			p.opens === "withdrawn"
				? { kind: "withdrawn" }
				: {
						kind: "opened",
						plaintext: new TextEncoder().encode(
							JSON.stringify(p.opens ?? { identifier: "alice", password: "pw" }),
						),
					},
		seal: async (_, info, aad, plaintext) => {
			if (p.sealFails) throw new TypeError("a sealing's fault");
			sealedTo.push({
				info,
				aad: new TextDecoder().decode(aad),
				plain: new TextDecoder().decode(plaintext),
			});
			return { enc: bytes(65, 4), ct: bytes(30, 5) };
		},
	};
	const told: string[] = [];
	const kind: FirstKeyEvidence = {
		kind: "password",
		check: async () => {
			if (p.answer === "throws") throw new Error("a kind's fault");
			return { kind: p.answer ?? "passed" };
		},
		settled: async (_, __, outcome) => {
			told.push(outcome);
		},
	};
	const issued: Passed[] = [];
	const ended: Ended[] = [];
	let dropped = 0;
	const dispatch = dispatchOver({
		max: p.max ?? 10,
		told: { dropped: () => dropped++, failed: () => {} },
	});
	if (p.started !== false) dispatch.start();
	const users = {
		byIdentifier: async (identifier: string): Promise<Verified> =>
			identifier === "alice"
				? { kind: "user", user: { subject: "s-alice", attributes: {} } }
				: { kind: "none" },
	};
	const start = startOver({
		keys,
		nonces,
		users,
		evidence: evidenceOver([kind], false),
		dispatch,
		issuing: async (passed) => {
			issued.push(passed);
			if (p.issued === "throws") throw new Error("a store's fault");
			return p.issued ?? "sent";
		},
		random: (n) => randomBytes(n),
		now: () => 700,
		ended: (e) => ended.push(e),
	});
	const request = async (): Promise<SealedRequest> => ({
		nonce: await nonces.issue("start"),
		...screenPoints(),
		enc: randomBytes(65),
		ct: bytes(40, 6),
	});
	const settle = () => dispatch.stop(new AbortController().signal);
	return { start, request, sealedTo, told, issued, ended, settle, nonces, dropped: () => dropped };
}

describe("a first key's start", () => {
	it("answers its code sealed to the screen under the code's info and the start's additional data", async () => {
		const w = await world();
		const r = await w.request();
		const started = await w.start(r);
		expect(started.kind).toBe("answered");
		const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
		const eSig = { kty: "EC", crv: "P-256", x: b64(r.eSigX), y: b64(r.eSigY) };
		expect(w.sealedTo).toHaveLength(1);
		expect(w.sealedTo[0]?.info).toBe(hpke.info.firstKeyCode);
		expect(w.sealedTo[0]?.aad).toBe(firstKey.aad("start", r.nonce, b64(r.eEnc), eSig as never));
		expect(JSON.parse(w.sealedTo[0]?.plain ?? "")).toEqual({
			code: expect.stringMatching(/^\d{8}$/),
		});
		await w.settle();
		expect(w.issued).toEqual([
			{
				subject: "s-alice",
				identifier: "alice",
				code: JSON.parse(w.sealedTo[0]?.plain ?? "").code,
				startedAt: 700,
			},
		]);
		expect(w.told).toEqual(["passed"]);
	});

	it("answers alike, one job put, for one named by no one and for evidence failed, issuing none", async () => {
		for (const [p, outcome] of [
			[{ opens: { identifier: "nobody", password: "pw" } }, "failed"],
			[{ answer: "failed" as const }, "failed"],
		] as const) {
			const w = await world(p);
			expect((await w.start(await w.request())).kind).toBe("answered");
			await w.settle();
			expect(w.issued).toEqual([]);
			expect(w.told).toEqual([outcome]);
			expect(w.ended).toHaveLength(1);
		}
	});

	it("tells the kinds the start failed where its subject holds a key or no mail went out", async () => {
		for (const issued of ["holds", "unreachable", "limited"] as const) {
			const w = await world({ issued });
			await w.start(await w.request());
			await w.settle();
			expect(w.told).toEqual(["failed"]);
			expect(w.ended[0]).toMatchObject({ checked: "passed", issued });
		}
	});

	it("refuses a nonce used before, and a request that does not open, sealing nothing", async () => {
		const w = await world();
		const r = await w.request();
		await w.start(r);
		expect(await w.start(r)).toEqual({ kind: "refused" });
		const odd = await world({ opens: { token: "t" } });
		expect(await odd.start(await odd.request())).toEqual({ kind: "refused" });
		expect(odd.sealedTo).toEqual([]);
		const withdrawn = await world({ opens: "withdrawn" });
		expect(await withdrawn.start(await withdrawn.request())).toEqual({ kind: "withdrawn" });
	});

	it("answers alike where the jobs are full or not yet started, the job dropped", async () => {
		for (const p of [{ max: 0 }, { started: false }]) {
			const w = await world(p);
			const started = await w.start(await w.request());
			expect(started.kind).toBe("answered");
			expect(w.dropped()).toBe(1);
		}
	});

	it("tells every kind unavailable where a kind faulted, or the job's own work did", async () => {
		for (const p of [{ answer: "throws" as const }, { issued: "throws" as const }]) {
			const w = await world(p);
			await w.start(await w.request());
			await w.settle();
			expect(w.ended[0]?.checked).toBe("unavailable");
			expect(w.ended[0]?.faults).toHaveLength(1);
			expect(w.told).toEqual(["unavailable"]);
		}
	});

	it("puts no job and seals nothing for screen keys of no point", async () => {
		const w = await world();
		const r = { ...(await w.request()), eEnc: bytes(65, 4) };
		expect(await w.start(r)).toEqual({ kind: "refused" });
		await w.settle();
		expect([w.sealedTo, w.ended]).toEqual([[], []]);
	});

	it("tells every kind unavailable, issuing nothing, where its code cannot be sealed", async () => {
		const w = await world({ sealFails: true });
		await expect(w.start(await w.request())).rejects.toThrow(TypeError);
		await w.settle();
		expect([w.issued, w.told]).toEqual([[], ["unavailable"]]);
		expect(w.ended[0]).toMatchObject({ checked: "unavailable" });
	});
});
