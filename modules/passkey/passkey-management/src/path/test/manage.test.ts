import { continuations } from "@mod/continuation-wire";
import { challengeInput, hpke } from "@mod/sdk-core-wire";
import { testOrigin } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import { b64, opened, payloadOf, screen, sha256, withFirstKey } from "./world.ts";

type Started = Awaited<ReturnType<typeof withFirstKey>>;
type Screen = Awaited<ReturnType<typeof screen>>;
const utf8 = (text: string) => new TextEncoder().encode(text);

/** A passkey-manage approved by alice's key, and the list its finish answers, opened. */
async function approved(k: Started) {
	const s = await screen();
	const started = await k.w.post("/approval/start", {
		purpose: "passkey-manage",
		eEnc: s.eEnc,
		eSigX: s.eSigX,
		eSigY: s.eSigY,
	});
	const statement = started.json.statement as string;
	const request = k.cer.request(sha256(challengeInput(statement, "get")), [], "required");
	const assertion = JSON.stringify(
		k.auth.get(request as never, { origin: testOrigin }, {}, k.key.id),
	);
	const finished = await k.w.post("/approval/finish", { statement, assertion });
	expect(finished.status).toBe(200);
	return {
		s,
		statement,
		hash: sha256(statement),
		assertion,
		list: await read(s, sha256(statement), finished.json),
	};
}

/** A completion the Core answered, opened as the screen opens it: its padded length and its payload. */
async function read(s: Screen, hash: string, json: Record<string, unknown>) {
	const text = await opened(
		s,
		json.sealed as never,
		hpke.info.completion,
		hpke.completionAad("passkey-manage", hash),
	);
	const jws = hpke.unpaddedCompletion(text ?? "");
	if (!jws) throw new Error("not padded to a bucket");
	return { length: (text ?? "").length, payload: payloadOf(jws) };
}

/** A rename sealed by the screen to the Core, signed by its E_sig, as `/continue`'s fields. */
async function renaming(k: Started, s: Screen, statement: string, seq: number, body: unknown) {
	const hash = sha256(statement);
	const bodyHash = sha256(continuations.bodyText("rename", body) as string);
	const sig = s.signs(continuations.of("rename", hash, seq, bodyHash));
	const plain = continuations.plainOf("rename", body, sig) as string;
	const box = await s.seal(
		k.w.corePoint,
		hpke.info.continuation,
		utf8(continuations.aad("rename", hash, seq)),
		utf8(plain),
	);
	return { statement, stage: "rename", seq: String(seq), enc: b64(box.enc), ct: b64(box.ct) };
}

describe("a person's keys listed and one renamed, from the approval to the list again, over real sealing", () => {
	it("lists alice's key, renames it, and answers the list again alike, each answer one length", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		expect(m.list.length).toBe(hpke.completionBuckets[0]);
		expect(m.list.payload).toMatchObject({
			purpose: "passkey-manage",
			t_hash: m.hash,
			assertion_hash: sha256(m.assertion),
			keys: [
				{ credential_id: k.key.id, label: expect.stringMatching(/^Passkey \d{4}-\d{2}-\d{2}$/) },
			],
		});
		const body = { credential_id: k.key.id, label: "Alice's laptop 💻" };
		const fields = await renaming(k, m.s, m.statement, 1, body);
		const answered = await k.w.post("/continue", fields);
		expect(answered.status).toBe(200);
		const after = await read(m.s, m.hash, answered.json);
		expect(after.length).toBe(m.list.length);
		expect(after.payload).toMatchObject({
			keys: [{ credential_id: k.key.id, label: "Alice's laptop 💻" }],
			continued: {
				stage: "rename",
				seq: 1,
				body_hash: sha256(continuations.bodyText("rename", body) as string),
			},
		});
		// The same continuation again: the answer kept, alike.
		expect((await k.w.post("/continue", fields)).json).toEqual(answered.json);
		// The same number with another body: refused, nothing renamed.
		const other = await renaming(k, m.s, m.statement, 1, { ...body, label: "x" });
		expect((await k.w.post("/continue", other)).json).toEqual({ error: "access_denied" });
		// A key none of alice's: the list unchanged, under the next number.
		const unknown = await renaming(k, m.s, m.statement, 2, { credential_id: "AQIDBA", label: "y" });
		const unchanged = await read(m.s, m.hash, (await k.w.post("/continue", unknown)).json);
		expect(unchanged.payload.keys).toEqual(after.payload.keys);
		expect(unchanged.payload.continued).toMatchObject({ seq: 2 });
	});

	it("runs a rename whose answer was lost again once its hold lapsed, answering alike from then on", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		const fields = await renaming(k, m.s, m.statement, 1, {
			credential_id: k.key.id,
			label: "laptop",
		});
		// The step renamed the key, then fell before its answer was kept.
		k.w.statements.fallAfter(m.hash, 1);
		await expect(k.w.post("/continue", fields)).rejects.toThrow("fell");
		// Meanwhile the same continuation is held: asked again later.
		expect((await k.w.post("/continue", fields)).status).not.toBe(200);
		k.w.advance(30_001);
		const again = await k.w.post("/continue", fields);
		expect(again.status).toBe(200);
		const read1 = await read(m.s, m.hash, again.json);
		expect(read1.payload.keys).toMatchObject([{ credential_id: k.key.id, label: "laptop" }]);
		expect((await k.w.post("/continue", fields)).json).toEqual(again.json);
		// The list as a new approval reads it: the label once, as given.
		expect((await approved(k)).list.payload.keys).toMatchObject([{ label: "laptop" }]);
	});

	it("refuses a rename sealed for another statement, or not sealed to the Core, as access_denied, writing nothing", async () => {
		const k = await withFirstKey();
		const m = await approved(k);
		const second = await approved(k);
		const body = { credential_id: k.key.id, label: "x" };
		// Sealed for the second statement, sent with the first.
		const elsewhere = await renaming(k, m.s, second.statement, 1, body);
		expect((await k.w.post("/continue", { ...elsewhere, statement: m.statement })).json).toEqual({
			error: "access_denied",
		});
		const again = await approved(k);
		expect(again.list.payload.keys).toEqual(m.list.payload.keys);
	});
});
