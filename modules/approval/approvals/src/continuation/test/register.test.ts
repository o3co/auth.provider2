import { continuations } from "@mod/continuation-wire";
import { describe, expect, it } from "vitest";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import { takenOverAfterMs } from "../continuation.ts";

const creationItems = {
	account: "a***@example",
	evidence: "ev",
	ct_hash: "ct",
	subject: "s1",
	kg: 0,
	options: {
		user_id: "u",
		rp_id: "rp.example",
		exclude_credentials: [],
		algorithms: [-7 as const],
	},
};

describe("a creation's continuation, its hold lapsed", () => {
	it("keeps the bytes of the call that took a number when another takes its lapsed hold", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const signed = () => keys.signs(continuations.of("register", c.hash, 1, sha256("b1")));
		const first = signed();
		const fell = w.approvals.continue({
			hash: c.hash,
			seq: 1,
			body: "b1",
			signature: first,
			step: async () => {
				throw new Error("fell");
			},
		});
		await expect(fell).rejects.toThrow("fell");
		// Taken, its answer not kept yet: what was sent is kept, with no answer.
		expect(w.statements.value(c.hash)).toMatchObject({
			seq: 1,
			sent: { body: "b1", signature: first },
		});
		expect(w.statements.value(c.hash)).not.toHaveProperty("result");
		w.advance(takenOverAfterMs + 1);
		await w.approvals.continue({
			hash: c.hash,
			seq: 1,
			body: "b1",
			signature: signed(),
			step: async () => "kept",
		});
		expect(w.statements.value(c.hash)).toMatchObject({
			seq: 1,
			sent: { body: "b1", signature: first },
			result: "kept",
		});
	});

	it("runs a step once for two calls at once, and again only once the call that held it let go", async () => {
		const w = await world();
		const keys = screenKeys();
		const c = await w.approvals.issue({
			purpose: "creation",
			items: creationItems,
			screen: keys.screen,
			by: "s",
		});
		if (c.kind !== "issued") throw new Error(c.reason);
		const signature = keys.signs(continuations.of("register", c.hash, 1, sha256("b1")));
		let release = () => {};
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		let runs = 0;
		const call = (step: () => Promise<string>) =>
			w.approvals.continue({ hash: c.hash, seq: 1, body: "b1", signature, step });
		const first = call(async () => {
			runs += 1;
			await held;
			throw new Error("lost");
		});
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(await call(async () => "second")).toEqual({ kind: "refused", reason: "pending" });
		const next = keys.signs(continuations.of("register", c.hash, 2, sha256("b2")));
		const two = await w.approvals.continue({
			hash: c.hash,
			seq: 2,
			body: "b2",
			signature: next,
			step: async () => 2,
		});
		expect(two).toEqual({ kind: "refused", reason: "seq" });
		release();
		await expect(first).rejects.toThrow("lost");
		expect(runs).toBe(1);
		expect(await call(async () => "again")).toEqual({ kind: "refused", reason: "pending" });
		w.advance(takenOverAfterMs + 1);
		expect(await call(async () => "again")).toEqual({
			kind: "continued",
			seq: 1,
			again: true,
			result: "again",
		});
	});
});
