import { continuations, type SealedStageName } from "@mod/continuation-wire";
import { hpke } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import type { OpenedBody, StepResult } from "../../contract.ts";
import { continuationsOver, takenOverAfterMs } from "../continuation.ts";

type World = Awaited<ReturnType<typeof world>>;
type Screen = ReturnType<typeof screenKeys>;
const utf8 = (text: string) => new TextEncoder().encode(text);
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const credentialId = "AQIDBA";
const renamed = (label: string) => ({ credential_id: credentialId, label });

/** A passkey-manage issued to the screen and used by s1's key. */
async function used(w: World, screen = screenKeys()) {
	await w.plant("s1");
	const a = await w.approvals.issue({
		purpose: "passkey-manage",
		items: {},
		screen: screen.screen,
		by: "src",
	});
	if (a.kind !== "issued") throw new Error(a.reason);
	const done = await w.approvals.use({ statement: a.statement, assertion: w.assert(a.challenge) });
	if (done.kind !== "approved") throw new Error(done.kind);
	return { ...a, screen };
}

/** A continuation sealed by the screen to the Core, as it seals one; each part may be made otherwise. */
async function sealed(
	w: World,
	s: Screen,
	hash: string,
	seq: number,
	body: unknown,
	o: {
		readonly stage?: SealedStageName;
		readonly signedAs?: { stage: SealedStageName; seq: number; body: unknown };
		readonly plain?: (padded: string) => string;
		readonly bytes?: (padded: Uint8Array) => Uint8Array;
		readonly aad?: string;
	} = {},
) {
	const stage = o.stage ?? "rename";
	const signed = o.signedAs ?? { stage, seq, body };
	const bodyHash = sha256(continuations.bodyText(signed.stage, signed.body) as string);
	const sig = s.signs(continuations.of(signed.stage, hash, signed.seq, bodyHash));
	const padded = continuations.plainOf(stage, body, sig) as string;
	const box = await w.keys.seal(
		w.corePoint,
		hpke.info.continuation,
		utf8(o.aad ?? continuations.aad(stage, hash, seq)),
		(o.bytes ?? ((b: Uint8Array) => b))(utf8(o.plain ? o.plain(padded) : padded)),
	);
	return { enc: b64(box.enc), ct: b64(box.ct) };
}

/** A step that notes what it was handed and answers the body's hash. */
function stepping() {
	const handed: unknown[] = [];
	return {
		handed,
		step: async (kept: unknown, opened: OpenedBody): Promise<StepResult> => {
			handed.push({ kept, opened });
			return { hash: opened.bodyHash };
		},
	};
}

describe("a sealed continuation", () => {
	it("hands its step the passkey-manage as kept and the body opened, keeping the answer and no text", async () => {
		const w = await world();
		const m = await used(w);
		const { handed, step } = stepping();
		const box = await sealed(w, m.screen, m.hash, 1, renamed("Laptop"));
		const q = { hash: m.hash, stage: "rename" as const, seq: 1, sealed: box, step };
		const bodyHash = sha256(continuations.bodyText("rename", renamed("Laptop")) as string);
		expect(await w.approvals.continueSealed(q)).toEqual({
			kind: "continued",
			seq: 1,
			again: false,
			result: { hash: bodyHash },
		});
		expect(handed).toEqual([
			{
				kept: {
					hash: m.hash,
					used: {
						statement: m.statement,
						assertion: expect.any(String),
						subject: "s1",
						credential: expect.any(String),
						registration: "r0",
						screen: m.screen.screen,
						mark: `statement:${JSON.parse(Buffer.from(m.statement.split(".")[1] ?? "", "base64url").toString()).sid}`,
					},
					until: expect.any(Number),
				},
				opened: {
					stage: "rename",
					body: renamed("Laptop"),
					bodyHash,
					signature: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/),
					heldUntil: expect.any(Number),
				},
			},
		]);
		// The same continuation again answers what was kept, its step not run again.
		expect(await w.approvals.continueSealed(q)).toMatchObject({ again: true });
		expect(handed).toHaveLength(1);
		const kept = w.statements.value(m.hash);
		expect(kept).not.toHaveProperty("sent");
		expect(JSON.stringify(kept)).not.toContain("Laptop");
		expect(kept).toMatchObject({ seq: 1, body: bodyHash, result: { hash: bodyHash } });
	});

	it("hands a number taken again the signature the write that took it kept, not a new one", async () => {
		const w = await world();
		const m = await used(w);
		const first = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const fell = async () => {
			throw new Error("fell");
		};
		await expect(
			w.approvals.continueSealed({
				hash: m.hash,
				stage: "rename",
				seq: 1,
				sealed: first,
				step: fell,
			}),
		).rejects.toThrow("fell");
		const kept = (w.statements.value(m.hash) as { sig: string }).sig;
		// The same number and body, signed and sealed again: another signature.
		w.advance(takenOverAfterMs + 1);
		const again = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const { handed, step } = stepping();
		await w.approvals.continueSealed({
			hash: m.hash,
			stage: "rename",
			seq: 1,
			sealed: again,
			step,
		});
		expect(handed).toMatchObject([{ opened: { signature: kept } }]);
	});

	it("takes a delete's number with the longest ID of the subject's keys then and the key it names", async () => {
		const w = await world();
		const m = await used(w);
		const { step } = stepping();
		const long = Buffer.alloc(129, 7).toString("base64url");
		const box = await sealed(w, m.screen, m.hash, 1, { credential_id: long }, { stage: "delete" });
		await w.approvals.continueSealed({ hash: m.hash, stage: "delete", seq: 1, sealed: box, step });
		// A key none of the subject's still sets its pad, so taken and not taken answer at one length.
		expect(w.statements.value(m.hash)).toMatchObject({ seq: 1, pad: 129 });
		// The next number, a rename's, keeps none.
		const two = await sealed(w, m.screen, m.hash, 2, renamed("x"));
		await w.approvals.continueSealed({ hash: m.hash, stage: "rename", seq: 2, sealed: two, step });
		expect(w.statements.value(m.hash)).not.toHaveProperty("pad");
	});

	it("takes the next number once the last is kept, and an earlier one again as seq", async () => {
		const w = await world();
		const m = await used(w);
		const { step } = stepping();
		const one = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const two = await sealed(w, m.screen, m.hash, 2, renamed("two"));
		const ask = (seq: number, box: typeof one) =>
			w.approvals.continueSealed({ hash: m.hash, stage: "rename", seq, sealed: box, step });
		expect(await ask(2, two)).toEqual({ kind: "refused", reason: "seq" });
		expect(await ask(1, one)).toMatchObject({ kind: "continued", seq: 1 });
		expect(await ask(2, two)).toMatchObject({
			kind: "continued",
			seq: 2,
		});
		expect(await ask(1, one)).toEqual({ kind: "refused", reason: "seq" });
	});

	it("refuses alike, writing nothing, a sealing that is not a used passkey-manage's continuation", async () => {
		const w = await world();
		const m = await used(w);
		const other = screenKeys();
		const { handed, step } = stepping();
		const body = renamed("x");
		const add = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: m.screen.screen,
			by: "src",
		});
		const issued = await w.approvals.issue({
			purpose: "passkey-manage",
			items: {},
			screen: m.screen.screen,
			by: "src",
		});
		if (add.kind !== "issued" || issued.kind !== "issued") throw new Error("not issued");
		await w.approvals.use({ statement: add.statement, assertion: w.assert(add.challenge) });
		const good = await sealed(w, m.screen, m.hash, 1, body);
		const short = await sealed(w, m.screen, m.hash, 1, body, { plain: (t) => t.trimEnd() });
		const cases: [string, { enc: string; ct: string }][] = [
			[m.hash, { ...good, ct: short.ct }],
			[m.hash, { ...good, enc: `${good.enc.slice(0, -1)}B` }],
			[m.hash, { ...good, enc: good.enc.slice(4) }],
			[add.hash, await sealed(w, m.screen, add.hash, 1, body)],
			[issued.hash, await sealed(w, m.screen, issued.hash, 1, body)],
			["unknown", good],
			[m.hash, await sealed(w, m.screen, m.hash, 1, body, { aad: "other" })],
			[
				m.hash,
				await sealed(w, m.screen, m.hash, 1, body, {
					stage: "rename",
					aad: continuations.aad("delete", m.hash, 1),
				}),
			],
			[m.hash, await sealed(w, m.screen, m.hash, 1, body, { plain: (t) => `${t.slice(0, -1)}x` })],
			[m.hash, await sealed(w, other, m.hash, 1, body)],
			[
				m.hash,
				await sealed(w, m.screen, m.hash, 1, body, {
					signedAs: { stage: "rename", seq: 1, body: renamed("y") },
				}),
			],
			[
				m.hash,
				await sealed(w, m.screen, m.hash, 1, body, { signedAs: { stage: "rename", seq: 2, body } }),
			],
		];
		const before = JSON.stringify(w.statements.value(m.hash));
		for (const [hash, box] of cases)
			expect(
				await w.approvals.continueSealed({ hash, stage: "rename", seq: 1, sealed: box, step }),
			).toEqual({ kind: "refused", reason: "sealed" });
		// A body of another stage's shape, sealed under that stage, read as a rename's: refused alike.
		const deleted = await sealed(
			w,
			m.screen,
			m.hash,
			1,
			{ credential_id: credentialId },
			{ stage: "delete" },
		);
		expect(
			await w.approvals.continueSealed({
				hash: m.hash,
				stage: "rename",
				seq: 1,
				sealed: deleted,
				step,
			}),
		).toEqual({ kind: "refused", reason: "sealed" });
		for (const seq of [0, 17, 1.5])
			expect(
				await w.approvals.continueSealed({
					hash: m.hash,
					stage: "rename",
					seq,
					sealed: good,
					step,
				}),
			).toEqual({ kind: "refused", reason: "seq" });
		expect(handed).toEqual([]);
		expect(JSON.stringify(w.statements.value(m.hash))).toBe(before);
	});

	it("takes a new number only before the statement expires, and runs a number taken to its end after", async () => {
		const w = await world();
		const m = await used(w);
		const box = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const q = { hash: m.hash, stage: "rename" as const, seq: 1, sealed: box };
		// The step fell: its number taken, nothing kept.
		const fell = async () => {
			throw new Error("fell");
		};
		// Taken just before the statement expires; past it, still held.
		w.advance(5 * 60_000 - 10_000);
		await expect(w.approvals.continueSealed({ ...q, step: fell })).rejects.toThrow("fell");
		w.advance(15_000);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toEqual({
			kind: "refused",
			reason: "pending",
		});
		w.advance(30_000);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toMatchObject({
			kind: "continued",
			seq: 1,
			again: true,
		});
		const two = await sealed(w, m.screen, m.hash, 2, renamed("two"));
		expect(
			await w.approvals.continueSealed({ ...q, seq: 2, sealed: two, step: stepping().step }),
		).toEqual({ kind: "refused", reason: "expired" });
	});

	it("takes no new number whose write comes past expiry, though checked before it", async () => {
		const w = await world();
		const m = await used(w);
		const { handed, step } = stepping();
		const box = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		w.advance(5 * 60_000 - 1);
		const before = JSON.stringify(w.statements.value(m.hash));
		// The store's write comes after the statement expired.
		w.statements.beforeChange(m.hash, async () => w.advance(2));
		expect(
			await w.approvals.continueSealed({
				hash: m.hash,
				stage: "rename",
				seq: 1,
				sealed: box,
				step,
			}),
		).toEqual({ kind: "refused", reason: "expired" });
		expect(handed).toEqual([]);
		expect(JSON.stringify(w.statements.value(m.hash))).toBe(before);
	});

	it("runs a number taken again only before its record's end", async () => {
		const w = await world();
		const m = await used(w);
		const { handed, step } = stepping();
		const box = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const q = { hash: m.hash, stage: "rename" as const, seq: 1, sealed: box };
		const fell = async () => {
			throw new Error("fell");
		};
		await expect(w.approvals.continueSealed({ ...q, step: fell })).rejects.toThrow("fell");
		w.advance(takenOverAfterMs + 1);
		// Its record held by a store past its end (its expiry moved back): still none runs past it.
		await w.statements.store.change(m.hash, (r) => ({
			value: {
				...(r as object),
				exp: (r as unknown as { exp: number }).exp - 10 * 60_000,
			} as never,
		}));
		expect(await w.approvals.continueSealed({ ...q, step })).toEqual({
			kind: "refused",
			reason: "expired",
		});
		expect(handed).toEqual([]);
	});

	it("hands its step when its record is gone, past which none of it runs", async () => {
		const w = await world();
		const m = await used(w);
		const { handed, step } = stepping();
		const box = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		await w.approvals.continueSealed({ hash: m.hash, stage: "rename", seq: 1, sealed: box, step });
		const exp = (w.statements.value(m.hash) as { exp: number }).exp;
		expect(handed).toMatchObject([{ kept: { until: exp + 60_000 } }]);
	});

	it("goes on from a passkey-manage whose list's completion is kept, and takes a delete alike", async () => {
		const w = await world();
		const m = await used(w);
		await w.statements.store.change(m.hash, (r) => ({
			value: { ...(r as object), state: "completed" } as never,
		}));
		const { handed, step } = stepping();
		const gone = { credential_id: credentialId };
		const box = await sealed(w, m.screen, m.hash, 1, gone, { stage: "delete" });
		expect(
			await w.approvals.continueSealed({
				hash: m.hash,
				stage: "delete",
				seq: 1,
				sealed: box,
				step,
			}),
		).toMatchObject({ kind: "continued", seq: 1, again: false });
		expect(handed).toMatchObject([{ opened: { stage: "delete", body: gone } }]);
	});

	it("refuses alike a statement this generation's ring does not verify, a text not UTF-8, and a body not canonical", async () => {
		const w = await world();
		const m = await used(w);
		const { handed, step } = stepping();
		const body = renamed("x");
		const ask = async (box: { enc: string; ct: string }) =>
			w.approvals.continueSealed({ hash: m.hash, stage: "rename", seq: 1, sealed: box, step });
		// Bytes no UTF-8 decoder takes, at the padded length.
		const broken = await sealed(w, m.screen, m.hash, 1, body, {
			bytes: (b) => Uint8Array.from(b, (x, i) => (i === b.length - 1 ? 0xff : x)),
		});
		// Its members in another order, padded alike: not the one text E_sig's body hash covers.
		const reordered = await sealed(w, m.screen, m.hash, 1, body, {
			plain: (t) => {
				const read = JSON.parse(t) as {
					body: { credential_id: string; label: string };
					sig: string;
				};
				const text = `{"sig":"${read.sig}","body":{"label":"${read.body.label}","credential_id":"${read.body.credential_id}"}}`;
				return text.padEnd(continuations.plainBytes, " ");
			},
		});
		expect(await ask(broken)).toEqual({ kind: "refused", reason: "sealed" });
		expect(await ask(reordered)).toEqual({ kind: "refused", reason: "sealed" });
		const good = await sealed(w, m.screen, m.hash, 1, body);
		const [head, payload] = m.statement.split(".");
		await w.statements.store.change(m.hash, (r) => ({
			value: {
				...(r as object),
				jws: `${head}.${payload}.${Buffer.alloc(64).toString("base64url")}`,
			} as never,
		}));
		expect(await ask(good)).toEqual({ kind: "refused", reason: "sealed" });
		expect(handed).toEqual([]);
		expect(w.statements.value(m.hash)).toMatchObject({ seq: 0 });
	});

	it("runs one step for two calls at once: the other pending, then answered again", async () => {
		const w = await world();
		const m = await used(w);
		let go = () => {};
		const gate = new Promise<void>((resolve) => {
			go = resolve;
		});
		let runs = 0;
		const step = async () => {
			runs++;
			await gate;
			return "done";
		};
		const box = await sealed(w, m.screen, m.hash, 1, renamed("one"));
		const q = { hash: m.hash, stage: "rename" as const, seq: 1, sealed: box, step };
		const first = w.approvals.continueSealed(q);
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(await w.approvals.continueSealed(q)).toEqual({ kind: "refused", reason: "pending" });
		go();
		expect(await first).toMatchObject({ kind: "continued", again: false, result: "done" });
		expect(await w.approvals.continueSealed(q)).toMatchObject({ kind: "continued", again: true });
		expect(runs).toBe(1);
	});

	it("throws where the keys' holder withdrew this Core's opening", async () => {
		const w = await world();
		const m = await used(w);
		const over = continuationsOver({
			keys: { verify: w.keys.verify, open: async () => ({ kind: "withdrawn" }) },
			list: { listOf: async () => [] },
			store: w.statements.store,
			now: () => Date.now(),
			token: () => "t",
		});
		const box = await sealed(w, m.screen, m.hash, 1, renamed("x"));
		await expect(
			over.continueSealed({
				hash: m.hash,
				stage: "rename",
				seq: 1,
				sealed: box,
				step: stepping().step,
			}),
		).rejects.toThrow();
	});
});

describe("a lapsed hold, taken over", () => {
	const fell = async () => {
		throw new Error("fell");
	};
	const box = async (w: World, m: Awaited<ReturnType<typeof used>>) => {
		const sealing = await sealed(
			w,
			m.screen,
			m.hash,
			1,
			{ credential_id: credentialId },
			{ stage: "delete" },
		);
		return { hash: m.hash, stage: "delete" as const, seq: 1, sealed: sealing };
	};

	it("takes a lapsed hold again only 2 seconds past its end; between, its completion is refused", async () => {
		const w = await world();
		const m = await used(w);
		const q = await box(w, m);
		await expect(w.approvals.continueSealed({ ...q, step: fell })).rejects.toThrow("fell");
		const pending = { kind: "refused", reason: "pending" };
		w.advance(30_001);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toEqual(pending);
		const bodyHash = sha256(
			continuations.bodyText("delete", { credential_id: credentialId }) as string,
		);
		const continued = { stage: "delete" as const, seq: 1, bodyHash, credential: credentialId };
		expect(
			await w.approvals.completePasskeyManage({
				hash: m.hash,
				continued: { ...continued, receipt: "h.p.s" },
			}),
		).toEqual({ kind: "refused", reason: "continued" });
		w.advance(1_999);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toEqual(pending);
		w.advance(1);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toMatchObject({
			kind: "continued",
			again: true,
		});
	});

	it("hands its step the end of its hold, never the 2 seconds past it", async () => {
		const w = await world();
		const m = await used(w);
		const q = await box(w, m);
		const { handed, step } = stepping();
		const taken = (w.statements.value(m.hash) as { exp: number }).exp - 5 * 60_000;
		await w.approvals.continueSealed({ ...q, step });
		expect(handed).toMatchObject([{ opened: { heldUntil: taken + 30_000 } }]);
	});

	it("takes again, before its record's end, a number taken at the statement's expiry", async () => {
		const w = await world();
		const m = await used(w);
		const q = await box(w, m);
		w.advance(5 * 60_000);
		await expect(w.approvals.continueSealed({ ...q, step: fell })).rejects.toThrow("fell");
		w.advance(takenOverAfterMs + 1);
		expect(await w.approvals.continueSealed({ ...q, step: stepping().step })).toMatchObject({
			kind: "continued",
			again: true,
		});
	});
});
