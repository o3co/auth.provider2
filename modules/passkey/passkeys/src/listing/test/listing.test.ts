import { continuations } from "@mod/continuation-wire";
import { payloads } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { world } from "../../../test/fixtures/world.ts";
import { keyList } from "../../contract.ts";
import { isKeyLabel, listingOver } from "../listing.ts";

const h = (c: string) => c.repeat(43);
const by = (seq: number, statement = h("A"), until = 2_000_000) => ({ statement, seq, until });

async function listed() {
	const w = await world();
	const list = await w.app.get(keyList);
	return { w, list };
}

describe("the keys' list", () => {
	it("lists each active key with the time it was reserved, and no label until one is given", async () => {
		const { w, list } = await listed();
		const first = await w.register("s1");
		w.advance(5000);
		const second = await w.register("s1", false);
		expect(await list.listOf("s1")).toEqual([
			{ credential: first.credential.id, createdAt: 1_000_000 },
			{ credential: second.credential.id, createdAt: 1_005_000 },
		]);
		expect(await list.listOf("s2")).toEqual([]);
	});

	it("leaves out a reserved key not yet active, and a time a record from before times lacks", async () => {
		const { w, list } = await listed();
		const first = await w.register("s1");
		const pending = await w.created();
		expect("reservation" in (await w.reserve({ subject: "s1", credential: pending }))).toBe(true);
		const record = w.credentials.value(first.credential.id) as { details: Record<string, unknown> };
		const { createdAt: _, ...details } = record.details;
		w.credentials.put(first.credential.id, { ...record, details });
		expect(await list.listOf("s1")).toEqual([{ credential: first.credential.id }]);
	});

	it("answers a step run again alike, and refuses an earlier number or its own with another label", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		const rename = { subject: "s1", credential: credential.id };
		expect(await list.rename({ ...rename, label: "one", by: by(2) })).toBe("renamed");
		const kept = w.credentials.value(credential.id);
		expect(await list.rename({ ...rename, label: "one", by: by(2) })).toBe("renamed");
		expect(w.credentials.value(credential.id)).toEqual(kept);
		expect(await list.rename({ ...rename, label: "late", by: by(1) })).toBe("stale");
		expect(await list.rename({ ...rename, label: "other", by: by(2) })).toBe("stale");
		expect(w.credentials.value(credential.id)).toEqual(kept);
		expect(await list.rename({ ...rename, label: "three", by: by(3) })).toBe("renamed");
		// Another statement's rename replaces the label, whatever its number.
		expect(await list.rename({ ...rename, label: "anew", by: by(1, h("B")) })).toBe("renamed");
		expect((await list.listOf("s1"))[0]?.label).toBe("anew");
	});

	it("refuses a paused step that wakes after later renames, of its statement or another, and one past its statement's end", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		const rename = { subject: "s1", credential: credential.id };
		// A/1 run by a call that took over its step, then A/2 and B/1: the first call of A/1 wakes last.
		expect(await list.rename({ ...rename, label: "a1", by: by(1) })).toBe("renamed");
		expect(await list.rename({ ...rename, label: "a2", by: by(2) })).toBe("renamed");
		expect(await list.rename({ ...rename, label: "b1", by: by(1, h("B")) })).toBe("renamed");
		expect(await list.rename({ ...rename, label: "a1", by: by(1) })).toBe("stale");
		expect((await list.listOf("s1"))[0]?.label).toBe("b1");
		// Past its statement's end, whatever was kept of it.
		const late = by(1, h("C"), 1_000_500);
		w.advance(1000);
		expect(await list.rename({ ...rename, label: "c1", by: late })).toBe("stale");
		// A statement whose end passed is no longer kept.
		expect(await list.rename({ ...rename, label: "d1", by: by(1, h("D"), 1_002_000) })).toBe(
			"renamed",
		);
		w.advance(5000);
		expect(await list.rename({ ...rename, label: "e1", by: by(1, h("E")) })).toBe("renamed");
		const kept = w.credentials.value(credential.id) as {
			details: { renames: { statement: string }[] };
		};
		expect(kept.details.renames.map((r) => r.statement)).toEqual([h("A"), h("B"), h("E")]);
	});

	it("renames no key but an active one of the subject's whose record keeps its details", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		await w.register("s2");
		const pending = await w.created();
		await w.reserve({ subject: "s1", credential: pending, generation: 0 });
		for (const [subject, id] of [
			["s2", credential.id],
			["s1", pending.id],
			["s1", "none"],
		] as const)
			expect(await list.rename({ subject, credential: id, label: "x", by: by(1) })).toBe("unknown");
		const record = w.credentials.value(credential.id) as Record<string, unknown>;
		const { details: _, ...bare } = record;
		w.credentials.put(credential.id, bare);
		expect(
			await list.rename({ subject: "s1", credential: credential.id, label: "x", by: by(1) }),
		).toBe("unknown");
		expect(w.credentials.value(credential.id)).toEqual(bare);
	});

	it("keeps only a label the list's form takes, so a list never fails on one kept", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		const taken = ["a", "x".repeat(64), "😀".repeat(64), 'quote " and \\ slash', "名前 الاسم"];
		// Format characters, separators, controls, a lone surrogate, too long, empty.
		const refused = ["a​b", "a‎b", "a b", "a\u0007b", "a\ud800b", "x".repeat(65), ""];
		for (const label of taken) expect(isKeyLabel(label)).toBe(true);
		for (const label of refused) {
			expect(isKeyLabel(label)).toBe(false);
			expect(
				await list.rename({ subject: "s1", credential: credential.id, label, by: by(1) }),
			).toBe("label");
		}
		const form = payloads.completions.passkeyManage;
		const completion = (label: string) => ({
			v: 1,
			iss: "https://core.example",
			t_hash: h("A"),
			assertion_hash: h("Q"),
			purpose: "passkey-manage",
			keys: [{ credential_id: "AQ", label, created_at: 0 }],
			iat: 0,
			exp: 1,
		});
		for (const label of [...taken, ...refused]) {
			expect(form.safeParse(completion(label)).success).toBe(isKeyLabel(label));
			// The rename's body takes the same: a label the screen sends is one a list carries.
			const body = { credential_id: "AQ", label };
			expect(continuations.bodies.rename.safeParse(body).success).toBe(isKeyLabel(label));
		}
	});

	it("gives a kept label only while it follows the rule, and throws a rename's `by` of another shape", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		const record = w.credentials.value(credential.id) as { details: Record<string, unknown> };
		w.credentials.put(credential.id, {
			...record,
			details: { ...record.details, label: "a\u200bb" },
		});
		expect(await list.listOf("s1")).toEqual([{ credential: credential.id, createdAt: 1_000_000 }]);
		const rename = { subject: "s1", credential: credential.id, label: "x" };
		const before = w.credentials.value(credential.id);
		for (const wrong of [
			{ ...by(1), statement: "" },
			{ ...by(1), seq: 0 },
			{ ...by(1), seq: 1.5 },
			{ ...by(1), seq: 2 ** 53 },
			{ ...by(1), until: Number.NaN },
		])
			await expect(list.rename({ ...rename, by: wrong })).rejects.toThrow(TypeError);
		expect(w.credentials.value(credential.id)).toEqual(before);
		// Its three fields alone are kept: the record reads after a `by` that carried more.
		const more = { ...by(1), extra: true } as ReturnType<typeof by>;
		expect(await list.rename({ ...rename, by: more })).toBe("renamed");
		expect((await list.listOf("s1"))[0]?.label).toBe("x");
		const kept = w.credentials.value(credential.id) as { details: { renames: object[] } };
		expect(kept.details.renames).toEqual([by(1)]);
	});
});

it("decides a rename's write by one reading of the clock, a paused step at its end stale still", async () => {
	const { w, list } = await listed();
	const { credential } = await w.register("s1");
	const rename = { subject: "s1", credential: credential.id };
	const end = 1_000_100;
	expect(await list.rename({ ...rename, label: "a1", by: by(1, h("A"), end) })).toBe("renamed");
	expect(await list.rename({ ...rename, label: "a2", by: by(2, h("A"), end) })).toBe("renamed");
	expect(await list.rename({ ...rename, label: "b1", by: by(1, h("B")) })).toBe("renamed");
	// A clock that moves on at every reading: at A's end for the first, past it for any after.
	let reading = end;
	const ticking = listingOver({
		frames: w.frames.frames,
		store: w.credentials.store,
		now: () => reading++,
	});
	expect(await ticking.rename({ ...rename, label: "a1", by: by(1, h("A"), end) })).toBe("stale");
	expect((await list.listOf("s1"))[0]?.label).toBe("b1");
});
