import { hpke, payloads, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { issued, payloadOf, possessionItems } from "../../../test/fixtures/statements.ts";
import { openSealed, screenKeys, world } from "../../../test/fixtures/world.ts";

describe("a key change's completion", () => {
	const named = { op: "add", credential_id: "cred", key_jkt: possessionItems.key_jkt };

	/** A possession issued for a screen, used by its pending key's verification. */
	async function usedPossession(w: Awaited<ReturnType<typeof world>>) {
		const keys = screenKeys();
		const p = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (p.kind !== "issued") throw new Error(p.reason);
		await w.approvals.use({ statement: p.statement, verification: "v1" });
		return { keys, p };
	}

	it("signs the key its possession names, sealed to its screen under its purpose and the possession's hash", async () => {
		const w = await world();
		const { keys, p } = await usedPossession(w);
		const asked = { hash: p.hash, purpose: "first-key" as const, receipt: "a.b.c" };
		const done = await w.approvals.completeKeyChange(asked);
		if (done.kind !== "completed") throw new Error(done.reason);
		const aad = hpke.completionAad("first-key", p.hash);
		const jws = openSealed(keys.encKey, done, hpke.info.completion, aad);
		expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
		const payload = payloadOf(jws);
		expect(payloads.completions.keyChange.safeParse(payload).success).toBe(true);
		expect(payload).toMatchObject({ purpose: "first-key", change: named, receipt: "a.b.c" });
		expect(payload.exp).toBe(payloadOf(p.statement).exp);
		// Under another purpose's additional data, or the bare hash, it does not open.
		for (const other of [hpke.completionAad("passkey-add", p.hash), p.hash]) {
			expect(() => openSealed(keys.encKey, done, hpke.info.completion, other)).toThrow();
		}
	});

	it("signs the possession's key, whatever else the caller hands", async () => {
		const w = await world();
		const { keys, p } = await usedPossession(w);
		const other = { op: "add", credential_id: "other", key_jkt: possessionItems.key_jkt };
		const asked = { hash: p.hash, purpose: "first-key" as const, change: other, extra: 1 };
		const done = await w.approvals.completeKeyChange(asked);
		if (done.kind !== "completed") throw new Error(done.reason);
		const aad = hpke.completionAad("first-key", p.hash);
		const payload = payloadOf(openSealed(keys.encKey, done, hpke.info.completion, aad));
		expect(payload.change).toEqual(named);
		expect(payload).not.toHaveProperty("extra");
	});

	it("signs no completion of a form sdk-core-wire refuses", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		expect(
			await w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key", receipt: "x" }),
		).toEqual({ kind: "refused", reason: "form" });
	});

	it("keeps one purpose of two asked at once, and refuses the other", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		const answers = await Promise.all([
			w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key" }),
			w.approvals.completeKeyChange({ hash: p.hash, purpose: "passkey-add" }),
		]);
		expect(answers.map((a) => a.kind).sort()).toEqual(["completed", "refused"]);
		expect(answers.find((a) => a.kind === "refused")).toEqual({ kind: "refused", reason: "other" });
	});

	it("answers the one kept for the same purpose, as the log first gave it, and refuses another", async () => {
		const w = await world();
		const { p } = await usedPossession(w);
		const [one, two] = await Promise.all([
			w.approvals.completeKeyChange({
				hash: p.hash,
				purpose: "passkey-add",
				status: '{"payload":"s"}',
			}),
			w.approvals.completeKeyChange({
				hash: p.hash,
				purpose: "passkey-add",
				status: '{"payload":"t"}',
			}),
		]);
		expect(one.kind).toBe("completed");
		expect(two).toEqual(one);
		expect(await w.approvals.completeKeyChange({ hash: p.hash, purpose: "first-key" })).toEqual({
			kind: "refused",
			reason: "other",
		});
	});

	it("answers no statement but a used possession unexpired, nor through the authorization's own calls", async () => {
		const w = await world();
		const t = await issued(w);
		const ask = (hash: string) =>
			w.approvals.completeKeyChange({ hash, purpose: "first-key" as const });
		expect(await ask(t.hash)).toEqual({ kind: "refused", reason: "purpose" });
		expect(await ask("none")).toEqual({ kind: "refused", reason: "unknown" });
		const keys = screenKeys();
		const unused = await w.approvals.issue({
			purpose: "possession",
			items: possessionItems,
			screen: keys.screen,
			by: "s",
		});
		if (unused.kind !== "issued") throw new Error(unused.reason);
		expect(await ask(unused.hash)).toEqual({ kind: "refused", reason: "unused" });
		const { p } = await usedPossession(w);
		const done = await ask(p.hash);
		expect(done.kind).toBe("completed");
		// A possession's completion is no authorization's: none is published nor given so.
		expect(await w.approvals.complete({ hash: p.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(await w.approvals.publish(p.hash)).toBe("unknown");
		expect(await w.approvals.completionOf(p.hash)).toBeUndefined();
		expect(await w.approvals.usedOf(p.hash)).toMatchObject({ completed: true });
		const late = await usedPossession(w);
		// Past its expiry, kept a minute more, a change placed late completed then; then gone.
		w.advance(5 * 60_000 + 1000);
		expect(await ask(late.p.hash)).toMatchObject({ kind: "completed" });
		const later = await usedPossession(w);
		w.advance(5 * 60_000 + 60_000);
		expect(await ask(later.p.hash)).toEqual({ kind: "refused", reason: "unknown" });
		w.advance(60_000);
		expect(await ask(late.p.hash)).toEqual({ kind: "refused", reason: "unknown" });
	});
});
