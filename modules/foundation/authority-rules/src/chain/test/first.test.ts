import { describe, expect, it } from "vitest";
import {
	addedKey,
	approval,
	askOf,
	continued,
	firstKey,
	firstKeyContinued,
	firstKeyEvidence,
	firstOver,
	newKey,
	prefixOf,
	type SignUpParts,
	type Step,
	signedUp,
	signUpParts,
} from "../../../test/fixtures/flow.ts";
import {
	assertion,
	authorization,
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

// A first key by the path its signed creation names (proposal 3.13, P 355 to 358): the first-key
// path's (`basis` none or `first-key`, no live key on the flow), its continuation checked where it
// carries one; a sign-up's (F1, `basis` `sign-up`), first trust where the subject's flow has no
// record before it, its T and continuation required. Rules023e `Allowed` `ft`.

const on = (steps: (Step & { judgment?: Finding })[]) => prefixOf(steps);
type Prefix = ReturnType<typeof on>;
const empty = on([]);
const verdictOn = (step: Step, p: Prefix = empty) => allowed(askOf(step, p.state, p.prior));
const ok = { allowed: true };
const refused = (reason: RegExp) => ({ allowed: false, reason: expect.stringMatching(reason) });

/** A sign-up whose parts are the honest ones but those given. */
const signUpWith = (over: Partial<SignUpParts>) => signedUp(1, { ...signUpParts(), ...over });
/** A sign-up's parts over another T, its creation and possession made for it. */
const forT = (t: string, basis: { basis: string; evidence: string } = signUpBasis(t)) => {
	const made = sign(creation(subject.id, undefined, 0, undefined, basis), "ring-1");
	const held = sign(possession(made, newKey), "ring-1");
	return {
		t,
		creation: made,
		continuation: continued(made, JSON.stringify(newKey)),
		possession: held,
		proof: assertion(newKey, held),
	};
};
const signUpBasis = (t: string) => ({ basis: "sign-up", evidence: digest(t) });

describe("a sign-up's key (F1; P 358: first trust where the subject first appears on the log)", () => {
	it("is allowed as its flow's first record, and is first trust: a key of no parent", () => {
		const step = signedUp(1);
		expect(verdictOn(step)).toEqual(ok);
		const ask = askOf(step, empty.state, empty.prior);
		expect(rootOf(ask)).toEqual({ first: true });
		expect(effectOf(ask)).toEqual({ key: newKey });
		// Its T is used by the approval after it, by the key it registered (the second tap).
		const p = on([step]);
		expect(p.state.keys["r-1"]).toMatchObject(newKey);
		expect(p.state.consumed).toEqual([]);
		expect(verdictOn(approval(2, "r-1", "signup-1"), p)).toEqual(ok);
	});

	it("is refused where its flow has a record before it, even one that left no live key (P 358 「すでに現れていれば不正」)", () => {
		expect(verdictOn(signedUp(2), on([firstKey(1)]))).toEqual(
			refused(/a sign-up's key is its first/),
		);
		const forged = on([{ ...firstKey(1), judgment: { verdict: "forged", outcome: "didNotTake" } }]);
		expect(Object.keys(forged.state.keys)).toEqual([]);
		// The first-key path's condition alone (no live key) would take it: a sign-up's is stricter.
		expect(verdictOn(firstKey(2), forged)).toEqual(ok);
		expect(verdictOn(signedUp(2), forged)).toEqual(refused(/a sign-up's key is its first/));
	});

	it("is refused unless its T, creation and possession verify by the writer generation's ring", () => {
		const parts = signUpParts();
		const t = sign(authorization("signup-1"), "ring-2");
		expect(verdictOn(signedUp(1, { ...parts, ...forT(t) }))).toEqual(refused(/T is not signed/));
		// A passkey-add's statement in T's place is no authorization's.
		const notT = sign(passkeyAdd("add-1"), "ring-1");
		expect(verdictOn(signedUp(1, { ...parts, ...forT(notT) }))).toEqual(refused(/T is not signed/));
		const unsigned = sign(
			creation(subject.id, undefined, 0, undefined, signUpBasis(parts.t)),
			"ring-2",
		);
		expect(verdictOn(signUpWith({ creation: unsigned }))).toEqual(refused(/not both signed/));
	});

	it("is refused for a creation not for its T, or naming another screen's keys than T's", () => {
		const parts = signUpParts();
		const other = sign(authorization("signup-2"), "ring-1");
		const elsewhere = forT(parts.t, signUpBasis(other));
		expect(verdictOn(signedUp(1, { ...parts, ...elsewhere }))).toEqual(refused(/not for its T/));
		const screened = sign({ ...authorization("signup-1"), e_enc: "b3RoZXI" }, "ring-1");
		expect(verdictOn(signedUp(1, { ...parts, ...forT(screened) }))).toEqual(
			refused(/another screen's keys than its T/),
		);
		const otherSig = { ...authorization("signup-1"), e_sig: { ...screen.e_sig, x: "eDI" } };
		expect(verdictOn(signedUp(1, { ...parts, ...forT(sign(otherSig, "ring-1")) }))).toEqual(
			refused(/another screen's keys than its T/),
		);
	});

	it("is refused unless the screen's continuation is its E_sig's over the creation, sending the record's key", () => {
		const parts = signUpParts();
		const forged = continued(parts.creation, JSON.stringify(newKey), 1, {
			...screen.e_sig,
			x: "eDk",
		});
		expect(verdictOn(signUpWith({ continuation: forged }))).toEqual(
			refused(/continuation is not the screen's/),
		);
		const another = continued(parts.creation, JSON.stringify(addedKey));
		expect(verdictOn(signUpWith({ continuation: another }))).toEqual(refused(/sends another key/));
		expect(verdictOn(signUpWith({ continuation: "{}" }))).toEqual(refused(/does not read/));
	});

	it("is refused without its T or continuation, or with them for a creation of another path", () => {
		const parts = signUpParts();
		// A sign-up's creation in the first-key path's order: its T and continuation are required.
		const bare = firstOver(
			1,
			[
				{ form: "statement", value: parts.creation },
				{ form: "statement", value: parts.possession },
				{ form: "assertion", value: parts.proof },
			],
			newKey,
			parts,
		);
		expect(verdictOn(bare)).toEqual(refused(/carries its T and continuation/));
		const continuedOnly = firstOver(
			1,
			[
				{ form: "statement", value: parts.creation },
				{ form: "continuation", value: parts.continuation },
				{ form: "statement", value: parts.possession },
				{ form: "assertion", value: parts.proof },
			],
			newKey,
			parts,
		);
		expect(verdictOn(continuedOnly)).toEqual(refused(/carries its T and continuation/));
		// The first-key path's creation after a T: a T is a sign-up's alone.
		const { creationJws, possessionJws } = firstKeyEvidence;
		const proof = assertion(newKey, possessionJws);
		const mixed = {
			t: parts.t,
			creation: creationJws,
			continuation: continued(creationJws, JSON.stringify(newKey)),
			possession: possessionJws,
			proof,
		};
		expect(verdictOn(signUpWith(mixed))).toEqual(refused(/T is a sign-up's alone/));
		// A passkey-add's creation is no first key's, by either order (Fable, the first-key path's `basis`).
		const add = forT(parts.t, { basis: "passkey-add", evidence: digest(parts.t) });
		expect(verdictOn(signedUp(1, { ...parts, ...add }))).toEqual(refused(/not for a first key/));
		const addBare = firstOver(
			1,
			[
				{ form: "statement", value: add.creation },
				{ form: "statement", value: add.possession },
				{ form: "assertion", value: add.proof },
			],
			newKey,
			add,
		);
		expect(verdictOn(addBare)).toEqual(refused(/not for a first key/));
	});

	it("is refused naming a parent or a root, on either path (Rules023e `ft`: par = 0)", () => {
		for (const step of [signedUp(1), firstKey(1)]) {
			const p = step.preimage as Record<string, unknown>;
			for (const named of [{ parent: "r-9" }, { root: "r-9" }])
				expect(verdictOn({ ...step, preimage: { ...p, ...named } })).toEqual(
					refused(/names no parent or root/),
				);
		}
	});

	it("is refused for its evidence out of order", () => {
		const parts = signUpParts();
		const swapped = firstOver(
			1,
			[
				{ form: "statement", value: parts.creation },
				{ form: "statement", value: parts.t },
				{ form: "continuation", value: parts.continuation },
				{ form: "statement", value: parts.possession },
				{ form: "assertion", value: parts.proof },
			],
			newKey,
			parts,
		);
		// The same forms in order, the T and the creation swapped: the creation does not read as one.
		expect(verdictOn(swapped)).toEqual(refused(/not both signed/));
		const reordered = firstOver(
			1,
			[
				{ form: "statement", value: parts.t },
				{ form: "continuation", value: parts.continuation },
				{ form: "statement", value: parts.creation },
				{ form: "statement", value: parts.possession },
				{ form: "assertion", value: parts.proof },
			],
			newKey,
			parts,
		);
		expect(verdictOn(reordered)).toEqual(refused(/in order/));
	});

	it("is refused where the signed bytes are not the record's, or its envelope names no digests", () => {
		const parts = signUpParts();
		const step = signedUp(1);
		const p = step.preimage as { content: Record<string, unknown> };
		const other = { ...step, preimage: { ...p, content: { ...p.content, credential: "cred-9" } } };
		expect(verdictOn(other)).toEqual(refused(/sends another key/));
		const proof = assertion(newKey, parts.creation);
		expect(verdictOn(signUpWith({ proof }))).toEqual(refused(/new key does not assert/));
		const { keyChange: _named, ...unnamed } = step.record as typeof step.record & {
			keyChange?: unknown;
		};
		expect(verdictOn({ ...step, record: unnamed as typeof step.record })).toEqual(
			refused(/names no key change's digests/),
		);
	});

	it("holds to its creation's and possession's times; its T's are its approval's (F1)", () => {
		const parts = signUpParts();
		const at = (step: Step, ms: number) => timely(askOf(step, empty.state, empty.prior), ms);
		const late = sign(authorization("signup-1", T0 - 1000), "ring-1");
		// A T past its lifetime does not hold the key's own time: the approval that uses it does.
		expect(at(signedUp(1, { ...parts, ...forT(late) }), T0 * 1000)).toBe(true);
		expect(at(signedUp(1), (T0 + 300) * 1000)).toBe(true);
		expect(at(signedUp(1), (T0 + 301) * 1000)).toBe(false);
	});
});

describe("the first-key path's continuation, checked where it carries one (P 355)", () => {
	it("is allowed with the screen's continuation over the creation, sending the record's key", () => {
		expect(verdictOn(firstKeyContinued(1))).toEqual(ok);
		expect(verdictOn(firstKey(1))).toEqual(ok);
	});

	it("is refused for a continuation sending another key, or not the screen's, or not read", () => {
		expect(verdictOn(firstKeyContinued(1, JSON.stringify(addedKey)))).toEqual(
			refused(/sends another key/),
		);
		const { creationJws, possessionJws } = firstKeyEvidence;
		const proof = assertion(newKey, possessionJws);
		const over = (value: string) =>
			firstOver(
				1,
				[
					{ form: "statement", value: creationJws },
					{ form: "continuation", value },
					{ form: "statement", value: possessionJws },
					{ form: "assertion", value: proof },
				],
				newKey,
				{ possession: possessionJws, proof },
			);
		const forged = continued(creationJws, JSON.stringify(newKey), 1, { ...screen.e_sig, x: "eDk" });
		expect(verdictOn(over(forged))).toEqual(refused(/continuation is not the screen's/));
		const otherCreation = continued(
			sign(creation(subject.id, T0 + 1), "ring-1"),
			JSON.stringify(newKey),
		);
		expect(verdictOn(over(otherCreation))).toEqual(refused(/continuation is not the screen's/));
		expect(verdictOn(over("not json"))).toEqual(refused(/does not read/));
	});
});
