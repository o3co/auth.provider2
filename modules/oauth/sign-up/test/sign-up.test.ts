import type { KeptSignUp, SignUpResult } from "@mod/approvals";
import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type SignUpParts, signUpStage, signUpStep, signUpsOver } from "../src/sign-up.ts";

// F1's step (f1-shape r3): counted, the subject made once by the ledger's idempotency key (T's
// hash), kept on T, its creation made; a refusal fixed for good kept, a passing one thrown.

const T0 = 1_800_000_000;
const kept: KeptSignUp = {
	hash: "t-hash",
	statement: "t-jws",
	issuedAt: T0 * 1000,
	items: {} as KeptSignUp["items"],
	screen: { eEnc: "enc", eSig: { kty: "EC", crv: "P-256", x: "x", y: "y" } },
};

function parts(over: Partial<SignUpParts> = {}) {
	const made: string[] = [];
	const asked: unknown[] = [];
	const hits: [string, string][] = [];
	const limited: string[] = [];
	const subjects = new Map<string, string>();
	const p: SignUpParts = {
		approvals: {
			continueSignUp: async () => {
				throw new Error("not asked");
			},
			signUpSubject: async (hash, subject) => {
				if (!subjects.has(hash)) subjects.set(hash, subject);
				return subjects.get(hash);
			},
		},
		createIdentifierless: async (key) => {
			made.push(key);
			return { subject: `sub-of-${key}` };
		},
		creations: {
			create: async (ask) => {
				asked.push(ask);
				return { kind: "issued", statement: "creation-jws", hash: "c", challenge: "ch" };
			},
		},
		limit: {
			hit: async (name, key) => {
				hits.push([name, key]);
				return { kind: "counted" } as never;
			},
		},
		window: { limit: 5, ms: 60_000 },
		total: 100,
		limited: (count) => {
			limited.push(count);
		},
		...over,
	};
	return { p, made, asked, hits, subjects, limited };
}

describe("a sign-up's step (F1)", () => {
	it("makes the subject under T's hash, keeps it on T, and answers the creation made for it", async () => {
		const w = parts();
		expect(await signUpStep(w.p)(kept, "src-1")).toEqual({ creation: "creation-jws" });
		expect(w.made).toEqual(["t-hash"]);
		expect(w.subjects.get("t-hash")).toBe("sub-of-t-hash");
		expect(w.asked).toEqual([
			{ tHash: "t-hash", subject: "sub-of-t-hash", screen: kept.screen, since: T0 * 1000 },
		]);
		expect(w.hits).toEqual([
			["sign-up.per-source", "src-1"],
			["sign-up.total", "all"],
		]);
	});

	it("asks the creation for the subject kept on T first, where another run kept one", async () => {
		const w = parts();
		w.subjects.set("t-hash", "kept-first");
		await signUpStep(w.p)(kept, "src-1");
		expect(w.asked).toMatchObject([{ subject: "kept-first" }]);
	});

	it("keeps its refusal for good, `revoked`, and throws a passing failure on so the step runs again", async () => {
		const revoked = parts({
			creations: { create: async () => ({ kind: "refused", reason: "revoked" }) },
		});
		expect(await signUpStep(revoked.p)(kept, "s")).toEqual({
			refused: "revoked",
		} satisfies SignUpResult);
		const passing = parts({
			creations: {
				create: async () => {
					throw new Unavailable("passkey-management");
				},
			},
		});
		await expect(signUpStep(passing.p)(kept, "s")).rejects.toBeInstanceOf(Unavailable);
	});

	it("throws, making no subject and telling which count, past its source's or every source's count", async () => {
		for (const [limitedOn, hit] of [
			["sign-up.per-source", ["sign-up.per-source"]],
			["sign-up.total", ["sign-up.per-source", "sign-up.total"]],
		] as const) {
			const w = parts();
			const hits: string[] = [];
			const p = {
				...w.p,
				limit: {
					hit: async (name: string) => {
						hits.push(name);
						return { kind: name === limitedOn ? "limited" : "counted" } as never;
					},
				},
			};
			await expect(signUpStep(p)(kept, "s")).rejects.toBeInstanceOf(Unavailable);
			expect(w.made).toEqual([]);
			// A source past its own count spends none of every source's.
			expect(hits).toEqual(hit);
			expect(w.limited).toEqual([limitedOn.slice("sign-up.".length)]);
		}
	});

	it("hands approvals' continueSignUp the continuation as read, and the step its source", async () => {
		const w = parts();
		const seen: unknown[] = [];
		const p = {
			...w.p,
			approvals: {
				...w.p.approvals,
				continueSignUp: async (q: Parameters<SignUpParts["approvals"]["continueSignUp"]>[0]) => {
					seen.push({ ...q, step: undefined });
					const result = await q.step(kept);
					return { kind: "continued" as const, seq: q.seq, again: false, result };
				},
			},
		};
		const ask = { hash: "t-hash", seq: 1, body: "{}", signature: "sig", source: "src-9" };
		expect(await signUpsOver(p)(ask)).toMatchObject({ result: { creation: "creation-jws" } });
		expect(seen).toEqual([
			{ hash: "t-hash", seq: 1, body: "{}", signature: "sig", step: undefined },
		]);
	});
});

describe("`/continue`'s stage `sign-up`", () => {
	const ask = {
		stage: "sign-up",
		source: "src-1",
		statement: "t",
		hash: "t-hash",
		seq: 1,
	} as const;
	const clear = { ...ask, body: "{}", signature: "sig" };
	const over = (continued: unknown) => signUpStage(async () => continued as never);

	it("answers the creation as a statement, and a refusal kept or taken by its reason", async () => {
		const ok = { kind: "continued", seq: 1, again: false };
		expect(await over({ ...ok, result: { creation: "c-jws" } }).continue(clear)).toEqual({
			kind: "statement",
			statement: "c-jws",
		});
		expect(await over({ ...ok, result: { refused: "revoked" } }).continue(clear)).toEqual({
			kind: "refused",
			reason: "revoked",
		});
		expect(await over({ kind: "refused", reason: "used" }).continue(clear)).toEqual({
			kind: "refused",
			reason: "used",
		});
		// The step kept neither: no answer this package made.
		await expect(over({ ...ok, result: { other: 1 } }).continue(clear)).rejects.toBeInstanceOf(
			TypeError,
		);
	});

	it("hands the continuation and its source on as read", async () => {
		const seen: unknown[] = [];
		const stage = signUpStage(async (q) => {
			seen.push(q);
			return { kind: "refused", reason: "used" };
		});
		await stage.continue(clear);
		expect(seen).toEqual([
			{ hash: "t-hash", seq: 1, body: "{}", signature: "sig", source: "src-1" },
		]);
	});

	it("throws where another call holds its step, or it came sealed", async () => {
		await expect(
			over({ kind: "refused", reason: "pending" }).continue(clear),
		).rejects.toBeInstanceOf(Unavailable);
		const sealed = { ...ask, sealed: { enc: "e", ct: "c" } };
		await expect(over({}).continue(sealed)).rejects.toBeInstanceOf(TypeError);
	});
});
