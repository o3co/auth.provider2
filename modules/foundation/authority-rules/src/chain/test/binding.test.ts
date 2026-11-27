import { describe, expect, it } from "vitest";
import {
	type AddParts,
	addBasis,
	added,
	addedKey,
	addParts,
	askOf,
	continued,
	firstKey,
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
	sign,
	subject,
} from "../../../test/fixtures/world.ts";
import type { Finding } from "../../fold/fold.ts";
import { allowed } from "../chain.ts";

// Proposal 3.13's checks a key change's possession binds, on each of its three paths (P 355: the
// reservation's id, the issuer read from the signed bytes): the possession names the reservation
// whose id is the record's op, and every statement of the preimage is one issuer's.

const on = (steps: (Step & { judgment?: Finding })[]) => prefixOf(steps);
type Prefix = ReturnType<typeof on>;
const verdictOn = (step: Step, p: Prefix = on([])) => allowed(askOf(step, p.state, p.prior));
const ok = { allowed: true };
const refused = (reason: RegExp) => ({ allowed: false, reason: expect.stringMatching(reason) });
const keyed = () => on([firstKey(1)]);
const otherIssuer = "https://other.example";

/** A step whose record is placed under another op than the reservation its possession names. */
const underOp = (step: Step, op: string): Step => ({
	...step,
	record: { ...(step.record as object), op } as Step["record"],
});

/** A possession of `creationJws` for `key`, signed by the ring but naming another issuer, and the key's assertion over it. */
const otherPossession = (creationJws: string, key: typeof newKey) => {
	const held = sign({ ...possession(creationJws, key), iss: otherIssuer }, "ring-1");
	return { possession: held, proof: assertion(key, held) };
};

/** A sign-up's parts for the T given, its creation and possession made for it. */
const signUpFor = (t: string): SignUpParts => {
	const basis = { basis: "sign-up", evidence: digest(t) };
	const made = sign(creation(subject.id, undefined, 0, undefined, basis), "ring-1");
	const held = sign(possession(made, newKey), "ring-1");
	return {
		reservation: "res-1",
		t,
		creation: made,
		continuation: continued(made, JSON.stringify(newKey)),
		possession: held,
		proof: assertion(newKey, held),
		key: newKey,
	};
};

/** A passkey-add's parts for the statement given, its creation and possession made for it. */
const addFor = (statement: string): AddParts => {
	const basis = addBasis(statement);
	const made = sign(creation(subject.id, undefined, 0, undefined, basis), "ring-1");
	const held = sign(possession(made, addedKey), "ring-1");
	return {
		reservation: "res-1",
		statement,
		asserted: assertion(newKey, statement),
		creation: made,
		continuation: continued(made, JSON.stringify(addedKey)),
		possession: held,
		proof: assertion(addedKey, held),
		key: addedKey,
	};
};

describe("the reservation a key change's possession names (P 355: 予約の id)", () => {
	it("is the record's op on the first-key path", () => {
		expect(verdictOn(firstKey(1))).toEqual(ok);
		expect(verdictOn(underOp(firstKey(1), "res-other"))).toEqual(
			refused(/another reservation than the op/),
		);
	});

	it("is the record's op on a sign-up's (F1)", () => {
		expect(verdictOn(signedUp(1))).toEqual(ok);
		expect(verdictOn(underOp(signedUp(1), "res-other"))).toEqual(
			refused(/another reservation than the op/),
		);
	});

	it("is the record's op on a passkey-add's", () => {
		expect(verdictOn(added(2, "r-1"), keyed())).toEqual(ok);
		expect(verdictOn(underOp(added(2, "r-1"), "res-other"), keyed())).toEqual(
			refused(/another reservation than the op/),
		);
	});

	it("is read from the signed possession: a retry's new reservation over the same creation passes under its own op alone", () => {
		// A retry (proposal 570): a second possession of the same creation, a new reservation and op.
		const { creationJws } = firstKeyEvidence;
		const held = sign(possession(creationJws, newKey, undefined, "res-other"), "ring-1");
		const proof = assertion(newKey, held);
		const step = firstOver(
			1,
			[
				{ form: "statement", value: creationJws },
				{ form: "continuation", value: continued(creationJws, JSON.stringify(newKey)) },
				{ form: "statement", value: held },
				{ form: "assertion", value: proof },
			],
			newKey,
			{ possession: held, proof },
		);
		expect(verdictOn(step)).toEqual(refused(/another reservation than the op/));
		expect(verdictOn(underOp(step, "res-other"))).toEqual(ok);
	});
});

describe("one issuer for a key change's statements (P 355: issuer, from the signed bytes)", () => {
	it("on the first-key path: the creation's and the possession's", () => {
		const { creationJws } = firstKeyEvidence;
		const other = otherPossession(creationJws, newKey);
		const step = firstOver(
			1,
			[
				{ form: "statement", value: creationJws },
				{ form: "continuation", value: continued(creationJws, JSON.stringify(newKey)) },
				{ form: "statement", value: other.possession },
				{ form: "assertion", value: other.proof },
			],
			newKey,
			other,
		);
		expect(verdictOn(step)).toEqual(refused(/not one issuer's/));
	});

	it("on a sign-up's (F1): T's, the creation's and the possession's", () => {
		const t = sign({ ...authorization("signup-1"), iss: otherIssuer }, "ring-1");
		expect(verdictOn(signedUp(1, signUpFor(t)))).toEqual(refused(/not one issuer's/));
		const parts = signUpParts();
		const other = otherPossession(parts.creation, newKey);
		expect(verdictOn(signedUp(1, { ...parts, ...other }))).toEqual(refused(/not one issuer's/));
	});

	it("on a passkey-add's: its statement's, the creation's and the possession's", () => {
		const statement = sign({ ...passkeyAdd("add-1"), iss: otherIssuer }, "ring-1");
		expect(verdictOn(added(2, "r-1", addFor(statement)), keyed())).toEqual(
			refused(/not one issuer's/),
		);
		const parts = addParts();
		const other = otherPossession(parts.creation, addedKey);
		expect(verdictOn(added(2, "r-1", { ...parts, ...other }), keyed())).toEqual(
			refused(/not one issuer's/),
		);
	});
});
