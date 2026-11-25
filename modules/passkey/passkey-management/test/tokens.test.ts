import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { StoredToken } from "../src/contract.ts";
import { codeOf, tokensOver } from "../src/tokens/tokens.ts";
import { memoryKept } from "./fixtures/kept.ts";

const eSig = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;
const q1 = { nonce: "n1", digest: "d1" };
const q2 = { nonce: "n2", digest: "d2" };
const right = "12345678";

function tokens(tries = 3) {
	const kept = memoryKept<StoredToken>();
	let now = 0;
	const over = tokensOver({
		store: kept.store,
		random: (n) => randomBytes(n),
		now: () => now,
		lifetimeMs: 900_000,
		tries,
	});
	return {
		...over,
		advance: (ms: number) => {
			now += ms;
			kept.advance(ms);
		},
		/** Moves the clock alone, the store keeping its records, as one whose lifetime ran later would. */
		later: (ms: number) => {
			now += ms;
		},
	};
}
const kind = async (tried: Promise<{ readonly kind: string }>) => (await tried).kind;

describe("a mail token", () => {
	it("is claimed by the request naming its subject and code, with its own subject and when its evidence began", async () => {
		const t = tokens();
		const { token, until } = await t.issue("s-alice", right, 250);
		expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(until).toBe(900_000);
		expect(await t.attempt(token, q1, "s-alice", right)).toEqual({
			kind: "claimed",
			subject: "s-alice",
			since: 250,
		});
	});

	it("is fixed to the request that claimed it: that one takes it up again, whatever subject it now names; any other is refused", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		await t.attempt(token, q1, "s-alice", right);
		expect(await t.attempt(token, q1, "s-bob", right)).toMatchObject({
			kind: "claimed",
			subject: "s-alice",
		});
		expect(await kind(t.attempt(token, q2, "s-alice", right))).toBe("refused");
	});

	it("counts each request once that names another subject, none, or another code, and is revoked at its tries", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		expect(await kind(t.attempt(token, q1, "s-bob", right))).toBe("refused");
		expect(await kind(t.attempt(token, q1, "s-bob", right))).toBe("refused");
		expect(await kind(t.attempt(token, q2, undefined, right))).toBe("refused");
		expect(await kind(t.attempt(token, { nonce: "n3", digest: "d3" }, "s-alice", "0"))).toBe(
			"refused",
		);
		expect(await kind(t.attempt(token, { nonce: "n4", digest: "d4" }, "s-alice", right))).toBe(
			"refused",
		);
	});

	it("is claimed by one of two right requests sent at once", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		const tried = await Promise.all([
			t.attempt(token, q1, "s-alice", right),
			t.attempt(token, q2, "s-alice", right),
		]);
		expect(tried.map((r) => r.kind).toSorted()).toEqual(["claimed", "refused"]);
	});

	it("holds no try past the end it was issued with, the store still keeping it, nor one never issued", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		const late = await t.issue("s-alice", right, 0);
		await t.attempt(token, q1, "s-alice", right);
		t.later(900_001);
		expect(await kind(t.attempt(late.token, q2, "s-alice", right))).toBe("refused");
		expect(await kind(t.attempt(token, q1, "s-alice", right))).toBe("refused");
		expect(await kind(t.attempt("none", q1, "s-alice", right))).toBe("refused");
	});
});

describe("a mail's side's answer", () => {
	it("is given only to its request, while its token is used by it, marking it used where it was claimed", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		await t.attempt(token, q1, "s-alice", right);
		await t.keep(q1, token, { eSig, statement: "s1" });
		expect(await t.answered({ nonce: "n1", digest: "other" })).toBeUndefined();
		expect(await t.answered(q1)).toBe("s1");
		expect(await kind(t.attempt(token, q1, "s-alice", right))).toBe("used");
		expect(await t.answered(q1)).toBe("s1");
		t.later(900_001);
		expect(await t.answered(q1)).toBeUndefined();
	});

	it("is kept once for its nonce, the first given after; a recovery reads its digest and E_sig, never its statement", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		await t.attempt(token, q1, "s-alice", right);
		await t.keep(q1, token, { eSig, statement: "s1" });
		await t.keep(q1, token, { eSig, statement: "s2" });
		expect(await t.recoverable("n1")).toEqual({ digest: "d1", eSig });
		expect(await t.answered(q1)).toBe("s1");
		expect(await t.recoverable("none")).toBeUndefined();
	});

	it("lives until its token's end and a minute, written late too", async () => {
		const t = tokens();
		const { token } = await t.issue("s-alice", right, 0);
		t.advance(600_000);
		await t.keep(q1, token, { eSig, statement: "s1" });
		t.advance(359_999);
		expect(await t.recoverable("n1")).toBeDefined();
		t.advance(1);
		expect(await t.recoverable("n1")).toBeUndefined();
	});
});

it("draws a code of eight digits, drawing again past the last whole hundred million", () => {
	const draws = [Buffer.from([0xff, 0xff, 0xff, 0xff]), Buffer.from([0, 0, 0, 42])];
	expect(codeOf(() => draws.shift() as Buffer)).toBe("00000042");
	expect(codeOf((n) => randomBytes(n))).toMatch(/^\d{8}$/);
});
