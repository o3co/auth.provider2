import { continuations } from "@mod/continuation-wire";
import { challengeInput } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { creationItems, issued, possessionItems } from "../../../test/fixtures/statements.ts";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";

describe("a continuation", () => {
	it("hands its step the creation as its record keeps it: the items signed and the screen's keys", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const handed: unknown[] = [];
		await w.approvals.continue({
			hash: c.hash,
			seq: 1,
			body: "b",
			signature: keys.signs(continuations.of("register", c.hash, 1, sha256("b"))),
			step: async (kept) => {
				handed.push(kept);
				return null;
			},
		});
		expect(handed).toEqual([{ items: creationItems, screen: keys.screen }]);
	});

	it("gives a creation's record, apart from a continuation, until it expires; no other purpose's", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued" || p.kind !== "issued") throw new Error("not issued");
		expect(await w.approvals.creationOf(c.hash)).toEqual({
			statement: c.statement,
			items: creationItems,
			screen: keys.screen,
		});
		expect(await w.approvals.creationOf(p.hash)).toBeUndefined();
		expect(await w.approvals.creationOf("unknown")).toBeUndefined();
		// A record whose bytes this generation's ring does not verify gives none.
		const [head, body] = c.statement.split(".");
		const other = `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`;
		await w.statements.store.change(c.hash, (r) => ({
			value: { ...(r as object), jws: other } as never,
		}));
		expect(await w.approvals.creationOf(c.hash)).toBeUndefined();
		const d = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (d.kind !== "issued") throw new Error(d.reason);
		expect(await w.approvals.creationOf(d.hash)).toBeDefined();
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.creationOf(d.hash)).toBeUndefined();
	});

	it("takes each next sequence number the screen signed, runs its step once and answers what it kept", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		expect(c.challenge).toBe(sha256(challengeInput(c.statement, "create")));
		let runs = 0;
		const step = (seq: number, body: string, signature?: string) =>
			w.approvals.continue({
				hash: c.hash,
				seq,
				body,
				signature: signature ?? keys.signs(continuations.of("register", c.hash, seq, sha256(body))),
				step: async () => {
					runs += 1;
					return { reserved: `${body}-${runs}` };
				},
			});
		expect(await step(1, "b1")).toEqual({
			kind: "continued",
			seq: 1,
			again: false,
			result: { reserved: "b1-1" },
		});
		expect(await step(1, "b1")).toEqual({
			kind: "continued",
			seq: 1,
			again: true,
			result: { reserved: "b1-1" },
		});
		expect(runs).toBe(1);
		expect(await step(1, "b2")).toEqual({ kind: "refused", reason: "seq" });
		expect(await step(3, "b3")).toEqual({ kind: "refused", reason: "seq" });
		const other = screenKeys().signs(continuations.of("register", c.hash, 2, sha256("b2")));
		expect(await step(2, "b2", other)).toEqual({ kind: "refused", reason: "signature" });
		expect(await step(2, "b2")).toMatchObject({
			kind: "continued",
			seq: 2,
			result: { reserved: "b2-2" },
		});
		const t = await issued(w);
		expect(
			await w.approvals.continue({
				hash: t.hash,
				seq: 1,
				body: "b",
				signature: "s",
				step: async () => null,
			}),
		).toEqual({ kind: "refused", reason: "purpose" });
	});

	it("refuses a body past 8192 bytes, and a signature in another spelling, taking nothing", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const ask = (body: string, signature: string) =>
			w.approvals.continue({ hash: c.hash, seq: 1, body, signature, step: async () => null });
		const big = "x".repeat(8193);
		expect(
			await ask(big, keys.signs(continuations.of("register", c.hash, 1, sha256(big)))),
		).toEqual({
			kind: "refused",
			reason: "body",
		});
		// The same 64 bytes, its last character's unused bits set: it verifies, and is refused.
		const sig = keys.signs(continuations.of("register", c.hash, 1, sha256("b1")));
		const last = sig.at(-1) as string;
		const spelt = `${sig.slice(0, -1)}${String.fromCharCode(last.charCodeAt(0) + 1)}`;
		expect(Buffer.from(spelt, "base64url")).toEqual(Buffer.from(sig, "base64url"));
		expect(await ask("b1", spelt)).toEqual({ kind: "refused", reason: "signature" });
		// Padded, of another length, or in base64's other alphabet: refused alike.
		const std = Buffer.from(sig, "base64url").toString("base64");
		for (const odd of [`${sig}==`, sig.slice(0, -2), `${sig}AA`, std.replace(/=+$/, "")])
			if (odd !== sig) expect(await ask("b1", odd)).toMatchObject({ reason: "signature" });
		// The bound counts UTF-8 bytes, not characters: 4096 two-byte characters pass, one more does not.
		const wide = "é".repeat(4096);
		const signedWide = (body: string) =>
			keys.signs(continuations.of("register", c.hash, 1, sha256(body)));
		expect(await ask(`${wide}é`, signedWide(`${wide}é`))).toEqual({
			kind: "refused",
			reason: "body",
		});
		expect(await ask(wide, signedWide(wide))).toMatchObject({ kind: "continued", seq: 1 });
		expect(w.statements.value(c.hash)).toMatchObject({ seq: 1 });
	});
});
