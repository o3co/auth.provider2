import { describe, expect, it } from "vitest";
import {
	added,
	addedKey,
	addParts,
	approval,
	askOf,
	codeBundle,
	codeStart,
	deletion,
	firstKey,
	newKey,
	prefixOf,
	refreshStart,
	type Step,
} from "../../../test/fixtures/flow.ts";
import { coseKey, T0 } from "../../../test/fixtures/world.ts";
import { allowed, effectOf, rootOf, timely } from "../../chain/chain.ts";
import type { Finding } from "../../fold/fold.ts";

// A key's deletion (V24, kernel-spec's note): approved by a live key, its `delete` continuation naming
// a live key of the flow, never the last; it drops that key and the families rooted in it alone.

type Prefix = ReturnType<typeof prefixOf>;
const on = (steps: (Step & { judgment?: Finding })[]): Prefix => prefixOf(steps);
const verdictOn = (step: Step, p: Prefix) => allowed(askOf(step, p.state, p.prior));
const ok = { allowed: true };
const refused = (reason: RegExp) => ({ allowed: false, reason: expect.stringMatching(reason) });
/** A first key (r-1, `newKey`) and the key it added (r-2, `addedKey`). */
const two = () => on([firstKey(1), added(2, "r-1")]);

describe("a key's deletion (V24)", () => {
	it("is allowed by a live key's approval of another live key, or of itself, and deletes it", () => {
		const p = two();
		const other = deletion(3, "r-1", addedKey.credential);
		expect(verdictOn(other, p)).toEqual(ok);
		expect(effectOf(askOf(other, p.state, p.prior))).toEqual({
			removeKey: "r-2",
			consume: ["statement:del-1"],
		});
		// The approving key deleting itself, the key it was added by left.
		const itself = deletion(3, "r-2", addedKey.credential, addedKey);
		expect(verdictOn(itself, p)).toEqual(ok);
		const above = deletion(3, "r-2", newKey.credential, addedKey);
		expect(verdictOn(above, p)).toEqual(ok);
		expect(effectOf(askOf(above, p.state, p.prior))).toMatchObject({ removeKey: "r-1" });
	});

	it("never deletes the flow's last key (KP-22): a reset, a denial or an erasure takes it", () => {
		const one = on([firstKey(1)]);
		expect(verdictOn(deletion(2, "r-1", newKey.credential), one)).toEqual(refused(/last key/));
	});

	it("is refused where the approving key is not live, or did not assert it, or the statement is used", () => {
		const p = two();
		expect(verdictOn(deletion(3, "r-9", addedKey.credential), p)).toEqual(
			refused(/approving key is not live/),
		);
		// r-1's key approving, the assertion made by r-2's.
		expect(verdictOn(deletion(3, "r-1", addedKey.credential, addedKey), p)).toEqual(
			refused(/assertion is not the approving key's/),
		);
		const used = { ...p, state: { ...p.state, consumed: ["statement:del-1"] } };
		expect(verdictOn(deletion(3, "r-1", addedKey.credential), used)).toEqual(
			refused(/statement is used/),
		);
	});

	it("is refused for a continuation of another stage, naming another key, or of no deletion's body", () => {
		const p = two();
		const renamed = deletion(3, "r-1", addedKey.credential, newKey, { stage: "rename" });
		expect(verdictOn(renamed, p)).toEqual(refused(/not the screen's over the passkey-manage/));
		const another = deletion(3, "r-1", addedKey.credential, newKey, { named: newKey.credential });
		expect(verdictOn(another, p)).toEqual(refused(/names another key/));
		const loose = deletion(3, "r-1", addedKey.credential, newKey, {
			body: JSON.stringify({ credential_id: addedKey.credential, label: "x" }),
		});
		expect(verdictOn(loose, p)).toEqual(refused(/body names no key/));
	});

	it("is refused for a key not live on the flow, its evidence out of order, or other envelope digests", () => {
		const p = two();
		expect(verdictOn(deletion(3, "r-1", "cred-9A", newKey, { named: "cred-9A" }), p)).toEqual(
			refused(/key it deletes is not live/),
		);
		const step = deletion(3, "r-1", addedKey.credential);
		const pre = step.preimage as { evidence: { form: string }[] };
		const swapped = { ...step, preimage: { ...pre, evidence: [...pre.evidence].reverse() } };
		expect(verdictOn(swapped, p)).toEqual(refused(/in order/));
		const record = {
			...step.record,
			keyChange: { statement: "a".repeat(43), evidence: "b".repeat(43) },
		};
		expect(verdictOn({ ...step, record }, p)).toEqual(
			refused(/other evidence than the preimage's/),
		);
	});

	it("holds to its passkey-manage's times, and rests on its approving key's root (J12, as an added key)", () => {
		const p = two();
		const step = deletion(3, "r-2", newKey.credential, addedKey);
		const ask = askOf(step, p.state, p.prior);
		expect(timely(ask, T0 * 1000)).toBe(true);
		expect(timely(ask, (T0 + 301) * 1000)).toBe(false);
		expect(rootOf(ask)).toEqual({ root: "r-1" });
	});

	it("rests on the deleted root's id where a key under a deleted root approves it (J12 reads chain[0])", () => {
		const third = { credential: "cred-3A", publicKey: coseKey(3) };
		const p = on([
			firstKey(1),
			added(2, "r-1"),
			added(3, "r-2", addParts("add-3", third, addedKey)),
			deletion(4, "r-2", newKey.credential, addedKey),
		]);
		expect(Object.keys(p.state.keys)).toEqual(["r-2", "r-3"]);
		const after = deletion(5, "r-3", addedKey.credential, third, { sid: "del-2" });
		expect(verdictOn(after, p)).toEqual(ok);
		expect(rootOf(askOf(after, p.state, p.prior))).toEqual({ root: "r-1" });
	});

	it("leaves the keys it did not name, folded as DelDrop", () => {
		const p = on([firstKey(1), added(2, "r-1"), deletion(3, "r-1", newKey.credential)]);
		expect(Object.keys(p.state.keys)).toEqual(["r-2"]);
	});

	it("leaves no family of the deleted key: its refresh, and a code's bundle on its approval, are refused (Rules023del)", () => {
		// r-1 approves a login whose bundle founds the family r-5; r-2, added by r-1, deletes r-1.
		const loggedIn = [
			firstKey(1),
			added(2, "r-1"),
			approval(3, "r-1"),
			codeStart(4, "login", "r-3"),
			codeBundle(5, "login", "r-4", "r-3"),
		];
		expect(verdictOn(refreshStart(6, "rf", "r-5"), on(loggedIn))).toEqual(ok);
		const p = on([...loggedIn, deletion(6, "r-2", newKey.credential, addedKey)]);
		expect(Object.keys(p.state.families)).toEqual([]);
		expect(verdictOn(refreshStart(7, "rf", "r-5"), p)).toEqual(refused(/family is not live/));
		// The code started before the deletion, its bundle after it.
		const started = on([...loggedIn.slice(0, 4), deletion(5, "r-2", newKey.credential, addedKey)]);
		expect(verdictOn(codeBundle(6, "login", "r-4", "r-3"), started)).toEqual(
			refused(/approval whose key is not live/),
		);
	});
});
