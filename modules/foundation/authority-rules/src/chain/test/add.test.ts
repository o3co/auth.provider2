import { createHash } from "node:crypto";
import { canonicalText, continuation } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import {
	type AddParts,
	added,
	addedKey,
	addParts,
	approval,
	askOf,
	continued,
	firstKey,
	newKey,
	prefixOf,
	type Step,
} from "../../../test/fixtures/flow.ts";
import {
	assertion,
	authorization,
	checks,
	coseKey,
	creation,
	digest,
	passkeyAdd,
	possession,
	screen,
	sign,
	subject,
	T0,
} from "../../../test/fixtures/world.ts";
import type { Finding } from "../../fold/fold.ts";
import { allowed, effectOf, rootOf, timely } from "../chain.ts";

// Proposal 3.13's order of a key's registration, its passkey-add root (P 355: the E keys the same
// from the passkey-add through the creation to the continuation, the continuation's key the
// possession's, one key from one root), and Rules023e `Allowed` `add` (par ∈ Keys(M)).

const on = (steps: (Step & { judgment?: Finding })[]) => prefixOf(steps);
type Prefix = ReturnType<typeof on>;
const verdictOn = (step: Step, p: Prefix) => allowed(askOf(step, p.state, p.prior));
const ok = { allowed: true };
const refused = (reason: RegExp) => ({ allowed: false, reason: expect.stringMatching(reason) });
const keyed = () => on([firstKey(1)]);
const addWith = (over: Partial<AddParts>) => added(2, "r-1", { ...addParts(), ...over });
const basis = (statement: string) => ({ basis: "passkey-add", evidence: digest(statement) });

describe("a key a live key's approval adds (passkey-add; Rules023e Allowed `add`)", () => {
	it("is allowed for a live key's approval and the screen's ceremony, and adds the key under it", () => {
		expect(verdictOn(added(2, "r-1"), keyed())).toEqual(ok);
		const p = on([firstKey(1), added(2, "r-1")]);
		expect(p.state.keys["r-2"]).toMatchObject({ ...addedKey, chain: ["r-1"] });
		expect(p.state.consumed).toEqual(["statement:add-1"]);
		// An added key approves the next, its chain from the first-trust key.
		const third = { credential: "cred-3", publicKey: coseKey(3) };
		const next = added(3, "r-2", addParts("add-2", third, addedKey));
		expect(verdictOn(next, p)).toEqual(ok);
		expect(on([firstKey(1), added(2, "r-1"), next]).state.keys["r-3"]?.chain).toEqual([
			"r-1",
			"r-2",
		]);
	});

	it("is refused unless the approving key is live on the flow: none, another record, or forged (par ∈ Keys(M))", () => {
		expect(verdictOn(added(1, "r-1"), on([]))).toEqual(refused(/approving key is not live/));
		expect(verdictOn(added(2, "r-9"), keyed())).toEqual(refused(/approving key is not live/));
		const forged = on([{ ...firstKey(1), judgment: { verdict: "forged", outcome: "didNotTake" } }]);
		expect(verdictOn(added(2, "r-1"), forged)).toEqual(refused(/approving key is not live/));
	});

	it("is refused unless the approving key asserts the passkey-add", () => {
		const parts = addParts();
		const other = sign(passkeyAdd("add-9"), "ring-1");
		for (const asserted of [assertion(addedKey, parts.statement), assertion(newKey, other)])
			expect(verdictOn(addWith({ asserted }), keyed())).toEqual(refused(/approving key's/));
	});

	it("adds one key from one passkey-add: a second one from it is refused (1 つの根拠から鍵は 1 本)", () => {
		const p = on([firstKey(1), added(2, "r-1")]);
		const again = added(
			3,
			"r-1",
			addParts("add-1", { credential: "cred-3", publicKey: coseKey(3) }),
		);
		expect(verdictOn(again, p)).toEqual(refused(/statement is used/));
		// The passkey-add's mark is in the approvals' space: an approval's statement of its sid is used too.
		const approved = on([firstKey(1), approval(2, "r-1", "add-1")]);
		expect(verdictOn(added(3, "r-1"), approved)).toEqual(refused(/statement is used/));
	});

	it("is refused for a credential the flow holds a live key of (the deletion and stateOf read a credential as one key)", () => {
		const again = { credential: newKey.credential, publicKey: coseKey(2) };
		expect(verdictOn(added(2, "r-1", addParts("add-1", again)), keyed())).toEqual(
			refused(/live key of that credential/),
		);
	});

	it("takes a continuation of any sequence number the screen signed, after a lost answer (seq 2)", () => {
		const parts = addParts();
		const sent = continued(parts.creation, JSON.stringify(addedKey), 2);
		expect(verdictOn(addWith({ continuation: sent }), keyed())).toEqual(ok);
	});

	it("is refused unless its passkey-add, creation and possession verify by the writer generation's ring", () => {
		const parts = addParts();
		const resigned = (jws: string) => `${jws.split(".").slice(0, 2).join(".")}.ring-2`;
		for (const over of [
			{ statement: resigned(parts.statement) },
			{ creation: resigned(parts.creation) },
			{ possession: resigned(parts.possession) },
			// An authorization's T is no passkey-add.
			{ statement: sign(authorization("add-1"), "ring-1") },
		])
			expect(verdictOn(addWith(over), keyed())).toEqual(refused(/writer generation's ring/));
	});

	it("is refused unless it carries its evidence in its one order, each once", () => {
		const step = added(2, "r-1");
		const evidence = (step.preimage as { evidence: { form: string; value: string }[] }).evidence;
		const at = (list: typeof evidence) => ({
			...step,
			preimage: { ...step.preimage, evidence: list },
		});
		for (const list of [
			evidence.slice(1),
			[...evidence, evidence[5]],
			[evidence[1], evidence[0], ...evidence.slice(2)],
			evidence.map((e) => (e.form === "continuation" ? { ...e, form: "completion" } : e)),
		])
			expect(verdictOn(at(list as typeof evidence), keyed())).toEqual(refused(/in order/));
	});

	it("is refused for a creation of another basis or evidence, subject or key generation than its passkey-add's", () => {
		const parts = addParts();
		const made = (subjectId: string, kg: number, b: { basis: string; evidence: string }) =>
			sign(creation(subjectId, T0, kg, undefined, b), "ring-1");
		const cases: [string, RegExp][] = [
			[
				made(subject.id, 0, { basis: "sign-up", evidence: digest(parts.statement) }),
				/not for its passkey-add/,
			],
			[made(subject.id, 0, basis("another statement")), /not for its passkey-add/],
			[made("sub-2", 0, basis(parts.statement)), /another subject's/],
			[made(subject.id, 1, basis(parts.statement)), /another key generation/],
		];
		for (const [c, reason] of cases)
			expect(verdictOn(addWith({ creation: c }), keyed())).toEqual(refused(reason));
	});

	it("is refused where the creation names another screen's keys than its passkey-add (P 355: the E keys the same)", () => {
		const parts = addParts();
		const of = (keys: object) =>
			sign(
				{ ...creation(subject.id, T0, 0, undefined, basis(parts.statement)), ...keys },
				"ring-1",
			);
		for (const keys of [{ e_enc: "b3RoZXI" }, { e_sig: { ...screen.e_sig, x: "eDI" } }])
			expect(verdictOn(addWith({ creation: of(keys) }), keyed())).toEqual(
				refused(/another screen's keys/),
			);
	});

	it("is refused unless the continuation is the screen's E_sig's over the creation: its key, creation, sequence", () => {
		const parts = addParts();
		const body = JSON.stringify(addedKey);
		const signedAs = (seq: number) => {
			const sent = JSON.parse(continued(parts.creation, body, seq));
			return canonicalText({ ...sent, seq: seq + 1 });
		};
		for (const sent of [
			continued(parts.creation, body, 1, { ...screen.e_sig, x: "eDI" }),
			continued(parts.possession, body),
			signedAs(1),
		])
			expect(verdictOn(addWith({ continuation: sent }), keyed())).toEqual(
				refused(/not the screen's over the creation/),
			);
	});

	it("verifies E_sig over the bytes approvals verifies: continuation.of over the creation's and the body's SHA-256", () => {
		const parts = addParts();
		const seen: string[] = [];
		const step = added(2, "r-1", parts);
		const ask = { ...askOf(step, keyed().state, keyed().prior) };
		const watching = {
			...ask,
			checks: {
				...checks,
				verifyEsig: (key: { x: string; y: string }, input: string, signature: string) => {
					seen.push(input);
					return checks.verifyEsig(key, input, signature);
				},
			},
		};
		expect(allowed(watching)).toEqual(ok);
		const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("base64url");
		const body = JSON.stringify(addedKey);
		expect(seen).toEqual([continuation.of("register", sha256(parts.creation), 1, sha256(body))]);
		expect(seen[0]).toBe(
			`{"body":"${sha256(body)}","h":"${sha256(parts.creation)}","seq":1,"stage":"register"}`,
		);
	});

	it("is refused unless the continuation reads, in its one canonical spelling", () => {
		const parts = addParts();
		const sent = JSON.parse(parts.continuation);
		for (const text of [
			JSON.stringify(sent, null, 1),
			JSON.stringify({ signature: sent.signature, body: sent.body, seq: sent.seq }),
			canonicalText({ ...sent, seq: 0 }),
			canonicalText({ ...sent, more: 1 }),
			"not json",
		])
			expect(verdictOn(addWith({ continuation: text }), keyed())).toEqual(refused(/does not read/));
	});

	it("is refused where the continuation sends another key or credential than the record's, or none", () => {
		const parts = addParts();
		for (const body of [
			JSON.stringify({ ...addedKey, credential: "cred-9" }),
			JSON.stringify({ ...addedKey, publicKey: coseKey(9) }),
			"no create() response",
		])
			expect(
				verdictOn(addWith({ continuation: continued(parts.creation, body) }), keyed()),
			).toEqual(refused(/another key than the record's/));
	});

	it("is refused unless the possession names the creation, the credential and the new key's thumbprint", () => {
		const parts = addParts();
		const own = possession(parts.creation, addedKey);
		const other = (p: object) =>
			sign({ ...own, possession: { ...own.possession, ...p } }, "ring-1");
		for (const p of [{ creation_hash: digest("another") }, { credential_id: "cred-9" }])
			expect(verdictOn(addWith({ possession: other(p) }), keyed())).toEqual(
				refused(/signed bytes are not the record's/),
			);
		expect(verdictOn(addWith({ possession: other({ key_jkt: digest("x") }) }), keyed())).toEqual(
			refused(/signed bytes are not the record's/),
		);
	});

	it("is refused unless the new key asserts the possession", () => {
		const parts = addParts();
		for (const proof of [assertion(newKey, parts.possession), assertion(addedKey, parts.creation)])
			expect(verdictOn(addWith({ proof }), keyed())).toEqual(refused(/new key does not assert/));
	});

	it("is refused where its envelope names other digests than its possession's and its new key's assertion's", () => {
		const step = added(2, "r-1");
		const named = (keyChange: { statement: string; evidence: string }) => ({
			...step,
			record: { ...step.record, keyChange },
		});
		const parts = addParts();
		const other = refused(/other evidence than the preimage's/);
		expect(
			verdictOn(
				named({ statement: digest(parts.statement), evidence: digest(parts.proof) }),
				keyed(),
			),
		).toEqual(other);
		expect(
			verdictOn(
				named({ statement: digest(parts.possession), evidence: digest(parts.asserted) }),
				keyed(),
			),
		).toEqual(other);
		// An envelope naming none is refused (P 581).
		const { keyChange: _named, ...unnamed } = step.record as typeof step.record & {
			keyChange?: unknown;
		};
		expect(verdictOn({ ...step, record: unnamed as typeof step.record }, keyed())).toEqual(
			refused(/names no key change's digests/),
		);
	});

	it("holds to each statement's times apart: the passkey-add's, the creation's, the possession's", () => {
		const parts = addParts();
		const at = (over: Partial<AddParts>, ms: number) =>
			timely(askOf(addWith(over), keyed().state, keyed().prior), ms);
		const late = sign(passkeyAdd("add-1", T0 + 100), "ring-1");
		expect(at({ statement: late }, T0 * 1000)).toBe(false);
		expect(at({ statement: late }, (T0 + 100) * 1000)).toBe(true);
		const early = (iat: number) => ({
			creation: sign(creation(subject.id, iat, 0, undefined, basis(parts.statement)), "ring-1"),
		});
		expect(at(early(T0 - 200), (T0 + 200) * 1000)).toBe(false);
		expect(at(early(T0 - 200), (T0 + 100) * 1000)).toBe(true);
		const proved = sign(possession(parts.creation, addedKey, T0 - 200), "ring-1");
		expect(at({ possession: proved }, (T0 + 200) * 1000)).toBe(false);
		expect(at({ possession: proved }, (T0 + 100) * 1000)).toBe(true);
	});

	it("rests on the approving key's root (J12), holds to its statements' times, and changes nothing where refused", () => {
		const p = on([firstKey(1), added(2, "r-1")]);
		const third = added(
			3,
			"r-2",
			addParts("add-2", { credential: "cred-3", publicKey: coseKey(3) }, addedKey),
		);
		expect(rootOf(askOf(added(2, "r-1"), keyed().state, keyed().prior))).toEqual({ root: "r-1" });
		expect(rootOf(askOf(third, p.state, p.prior))).toEqual({ root: "r-1" });
		expect(rootOf(askOf(added(2, "r-9"), keyed().state, keyed().prior))).toBeUndefined();
		const at = (ms: number) => timely(askOf(added(2, "r-1"), keyed().state, keyed().prior), ms);
		expect(at(T0 * 1000)).toBe(true);
		expect(at((T0 + 300) * 1000)).toBe(true);
		expect(at(T0 * 1000 - 1)).toBe(false);
		expect(at((T0 + 300) * 1000 + 1)).toBe(false);
		const of = (step: Step) => effectOf(askOf(step, keyed().state, keyed().prior));
		expect(of(added(2, "r-1"))).toEqual({
			key: { ...addedKey, by: "r-1" },
			consume: ["statement:add-1"],
		});
		expect(of(addWith({ continuation: "not json" }))).toEqual({});
	});
});
