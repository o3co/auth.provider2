import { describe, expect, it } from "vitest";
import {
	approval,
	askOf,
	codeBundle,
	codeStart,
	firstKey,
	firstKeyEvidence,
	login,
	newKey,
	prefixOf,
	refreshBundle,
	refreshStart,
	type Step,
} from "../../../test/fixtures/flow.ts";
import {
	assertion,
	authorization,
	checks,
	context,
	coreRecord,
	coseKey,
	creation,
	digest,
	limits,
	point,
	possession,
	preimage,
	sign,
	subject,
} from "../../../test/fixtures/world.ts";
import { emptyState, type Finding, type FlowState } from "../../fold/fold.ts";
import { allowed, effectOf, timely } from "../chain.ts";

// Each case names the model definition or judgment row it is taken from: Rules023e.tla `Allowed`
// (ft: no live key, the writer's ring, the boundary; add/fam: par ∈ Keys(M); ref: par ∈ Fams(M)),
// Step023.tla `Allowed` and `AbnFam`, BundleEscape023.tla `BundleVerdict`, and kernel-spec §6.1 J7.

type Prefix = { state: FlowState; prior: ReturnType<typeof prefixOf>["prior"] };
const on = (steps: (Step & { judgment?: Finding })[]): Prefix => prefixOf(steps);
const verdictOn = (step: Step, p: Prefix) => allowed(askOf(step, p.state, p.prior));
const ok = { allowed: true };
const refused = (reason: RegExp) => ({ allowed: false, reason: expect.stringMatching(reason) });
const empty: Prefix = { state: emptyState, prior: [] };

describe("a first-trust key (Rules023e Allowed `ft`)", () => {
	it("is allowed on a flow with no live key, by the writer generation's ring, at the flow's key generation", () => {
		expect(verdictOn(firstKey(1), empty)).toEqual(ok);
	});

	it("is refused on a flow with a live key (P 354; UserRetry)", () => {
		expect(verdictOn(firstKey(2), on([firstKey(1)]))).toEqual(refused(/live key/));
	});

	it("is refused unless both its creation and its possession verify by the writer generation's ring (RingCheck `any`, `none`: W_OldGenBad, W_HoardBad, W_FabBad)", () => {
		const step = firstKey(1);
		const other = { ...askOf(step, emptyState, []), context: context(2) };
		expect(allowed(other)).toEqual(refused(/ring/));
		const fabricated = {
			...step,
			preimage: preimage({
				evidence: [{ form: "assertion", value: assertion(newKey, "x") }],
				content: { variant: "first", ...newKey },
			}),
		};
		expect(verdictOn(fabricated, empty)).toEqual(refused(/ring/));
	});

	it("is refused for a creation signed for another key generation, read from the signed bytes (BndCheck, BindGen: W_PreResetBad; J7 境界の後の古い鍵の世代)", () => {
		expect(verdictOn(firstKey(1, 1), empty)).toEqual(refused(/key generation/));
		const step = firstKey(1, 0);
		const p = step.preimage as { content: Record<string, unknown> };
		const restated = { ...step, preimage: { ...p, content: { ...p.content, keyGeneration: 1 } } };
		expect(verdictOn(restated, { ...empty, state: { ...emptyState, keyGeneration: 1 } })).toEqual(
			refused(/content/),
		);
		expect(
			verdictOn(firstKey(1, 0), { ...empty, state: { ...emptyState, keyGeneration: 1 } }),
		).toEqual(refused(/key generation/));
	});

	it("is refused where the signed bytes are not the record's: another subject, key or credential (OI-22)", () => {
		const { creationJws, possessionJws } = firstKeyEvidence;
		const evidence = (c: string, p: string, key = newKey) => [
			{ form: "statement", value: c },
			{ form: "statement", value: p },
			{ form: "assertion", value: assertion(key, p) },
		];
		const content = (key: typeof newKey) => ({ variant: "first", ...key });
		const otherSubject = sign(creation("sub-2"), "ring-1");
		const step = (c: string, p: string, key = newKey) => ({
			record: coreRecord("keyChange", 1),
			preimage: preimage({ evidence: evidence(c, p, key), content: content(key) }),
		});
		expect(
			verdictOn(step(otherSubject, sign(possession(otherSubject, newKey), "ring-1")), empty),
		).toEqual(refused(/subject/));
		const swapped = { credential: "cred-2", publicKey: point(2) };
		expect(verdictOn(step(creationJws, possessionJws, swapped), empty)).toEqual(
			refused(/signed bytes/),
		);
		const loose = sign(possession(sign(creation(subject.id, 1), "ring-1"), newKey), "ring-1");
		expect(verdictOn(step(creationJws, loose), empty)).toEqual(refused(/signed bytes/));
		const notPoint = { credential: newKey.credential, publicKey: "cGstMQ" };
		expect(verdictOn(step(creationJws, possessionJws, notPoint), empty)).toEqual(
			refused(/uncompressed P-256 point/),
		);
	});

	it("takes a new key named by its thumbprint: one the protocol takes, of an algorithm the creation offered (V22)", () => {
		const step = (
			key: { credential: string; publicKey: string },
			offered?: number[] | "none",
			c = checks,
		) => {
			const made = creation(subject.id, undefined, 0, offered === "none" ? undefined : offered);
			const { algorithms: _, ...options } = made.creation.options;
			const named =
				offered === "none" ? { ...made, creation: { ...made.creation, options } } : made;
			const creationJws = sign(named, "ring-1");
			const possessionJws = sign(possession(creationJws, key), "ring-1");
			const s: Step = {
				record: coreRecord("keyChange", 1),
				preimage: preimage({
					evidence: [
						{ form: "statement", value: creationJws },
						{ form: "statement", value: possessionJws },
						{ form: "assertion", value: assertion(key, possessionJws) },
					],
					content: { variant: "first", ...key },
				}),
			};
			return allowed({ ...askOf(s, emptyState, []), checks: c });
		};
		for (const alg of [-7, -8, -257])
			expect(step({ credential: "c", publicKey: coseKey(1, alg) })).toEqual(ok);
		const eddsa = { credential: "c", publicKey: coseKey(1, -8) };
		expect(step(eddsa, [-7])).toEqual(refused(/algorithm is not one the creation offered/));
		expect(step(eddsa, "none")).toEqual(refused(/algorithm is not one the creation offered/));
		const { keyThumbprint: __, ...without } = checks;
		expect(step(eddsa, undefined, without)).toEqual(refused(/not a key the protocol takes/));
		const unread = { ...checks, keyThumbprint: () => undefined };
		expect(step(eddsa, undefined, unread)).toEqual(refused(/not a key the protocol takes/));
		const other = { ...checks, keyThumbprint: () => ({ jkt: digest("other"), alg: -8 }) };
		expect(step(eddsa, undefined, other)).toEqual(refused(/signed bytes/));
	});

	it("is refused unless the new key asserts the possession", () => {
		const step = firstKey(1);
		const p = step.preimage as { evidence: { form: string; value: string }[] };
		const evidence = p.evidence.map((e) =>
			e.form === "assertion" ? { ...e, value: assertion(newKey, firstKeyEvidence.creationJws) } : e,
		);
		expect(verdictOn({ ...step, preimage: { ...p, evidence } }, empty)).toEqual(refused(/assert/));
	});

	it("is refused off a subject flow, at a stage not its op's only one, or with content of another kind", () => {
		const step = firstKey(1);
		const client = { ...step, record: { ...step.record, flow: { of: "client", id: "rp" } } };
		expect(verdictOn(client as Step, empty)).toEqual(refused(/subject flow/));
		expect(verdictOn({ ...step, record: { ...step.record, last: false } }, empty)).toEqual(
			refused(/one stage/),
		);
		const content = preimage({ content: { variant: "remove", key: "r-1" } });
		expect(verdictOn({ ...step, preimage: content }, empty)).toEqual(refused(/content/));
	});
});

describe("an approval (Rules023e Allowed `add`/`fam`: par ∈ Keys(M); J7)", () => {
	const withKey = () => on([firstKey(1)]);

	it("is allowed for a live key's assertion over a statement of the writer generation's ring", () => {
		expect(verdictOn(approval(2, "r-1"), withKey())).toEqual(ok);
	});

	it("is refused for a key that is not live: never folded, removed, denied, or of a forged parent (J7 不正な親の子孫, 削除の後の消した鍵の承認)", () => {
		expect(verdictOn(approval(2, "r-1"), empty)).toEqual(refused(/not live/));
		const forgedKey = on([
			{ ...firstKey(1), judgment: { verdict: "forged", outcome: "didNotTake" } },
		]);
		expect(verdictOn(approval(2, "r-1"), forgedKey)).toEqual(refused(/not live/));
	});

	it("is refused unless the key asserts the statement, and the statement is the writer generation's ring's", () => {
		const step = approval(2, "r-1");
		const p = step.preimage as { evidence: { form: string; value: string }[] };
		const other = sign(authorization("sid-9"), "ring-1");
		const evidence = p.evidence.map((e) =>
			e.form === "assertion" ? { ...e, value: assertion(newKey, other) } : e,
		);
		expect(verdictOn({ ...step, preimage: { ...p, evidence } }, withKey())).toEqual(
			refused(/assert/),
		);
		expect(allowed({ ...askOf(step, withKey().state, []), context: context(2) })).toEqual(
			refused(/ring/),
		);
	});

	it("is refused for a statement already used (消費の印)", () => {
		const p = on([firstKey(1), approval(2, "r-1")]);
		expect(verdictOn(approval(3, "r-1"), p)).toEqual(refused(/used/));
		expect(verdictOn(approval(3, "r-1", "sid-2"), p)).toEqual(ok);
	});

	it("is refused where the envelope binds other evidence than the preimage's", () => {
		const step = approval(2, "r-1");
		const record = {
			...step.record,
			approval: { statement: digest("x"), assertion: digest("y"), code: digest("z") },
		};
		expect(verdictOn({ ...step, record }, withKey())).toEqual(refused(/binds/));
		const { approval: _none, ...bare } = step.record as typeof step.record & { approval?: unknown };
		expect(verdictOn({ ...step, record: bare as typeof step.record }, withKey())).toEqual(
			refused(/binds/),
		);
	});
});

describe("a code exchange: start and bundle (J2, J7, BundleEscape023)", () => {
	const approved = () => on([firstKey(1), approval(2, "r-1")]);

	it("allows a start of a live approval's code at its op's first stage, and its bundle after it", () => {
		expect(verdictOn(codeStart(3, "login", "r-2"), approved())).toEqual(ok);
		const started = on([...login().slice(0, 3)]);
		expect(verdictOn(codeBundle(4, "login", "r-3", "r-2"), started)).toEqual(ok);
	});

	it("refuses a start of an approval that is not live, or at the op's last stage", () => {
		expect(verdictOn(codeStart(2, "login", "r-2"), on([firstKey(1)]))).toEqual(refused(/not live/));
		const step = codeStart(3, "login", "r-2");
		expect(verdictOn({ ...step, record: { ...step.record, last: true } }, approved())).toEqual(
			refused(/first stage/),
		);
	});

	it("refuses a second start from one approval, whatever the first one's verdict (J2: 受け付けた開始を全部数える)", () => {
		for (const judgment of [
			{ verdict: "held", outcome: "didNotTake" },
			{ verdict: "forged", outcome: "didNotTake" },
			{ verdict: "verified", outcome: "didNotTake" },
		] as const) {
			const p = on([
				firstKey(1),
				approval(2, "r-1"),
				{ ...codeStart(3, "login", "r-2"), judgment },
			]);
			expect(verdictOn(codeStart(4, "again", "r-2"), p)).toEqual(refused(/once/));
		}
	});

	it("refuses a bundle with no start of its op before it, or naming another start or root", () => {
		expect(verdictOn(codeBundle(3, "login", "r-9", "r-2"), approved())).toEqual(
			refused(/no start/),
		);
		const started = on(login().slice(0, 3));
		expect(verdictOn(codeBundle(4, "login", "r-9", "r-2"), started)).toEqual(
			refused(/another start/),
		);
		const p2 = on([
			...login().slice(0, 2),
			approval(3, "r-1", "sid-2"),
			codeStart(4, "login", "r-2"),
		]);
		expect(verdictOn(codeBundle(5, "login", "r-4", "r-3"), p2)).toEqual(refused(/roots elsewhere/));
	});

	it("refuses a bundle after its start was judged acceptable but did not take (BundleEscape023 `sv = ok /\\ ~StartDone`)", () => {
		const steps = login();
		for (const verdict of ["verified", "unsupported"] as const) {
			const p = on([
				...steps.slice(0, 2),
				{ ...(steps[2] as Step), judgment: { verdict, outcome: "didNotTake" } },
			]);
			expect(verdictOn(steps[3] as Step, p)).toEqual(refused(/did not take/));
		}
	});

	it("leaves the start's root to J9 when the start is held, its own root still held to the state (KG-01, KG-20)", () => {
		const steps = login();
		const held = { verdict: "held", outcome: "didNotTake" } as const;
		const p = on([...steps.slice(0, 2), { ...(steps[2] as Step), judgment: held }]);
		p.prior[2] = { ...(p.prior[2] as (typeof p.prior)[number]), parent: undefined };
		expect(verdictOn(steps[3] as Step, p)).toEqual(ok);
		expect(verdictOn(codeBundle(4, "login", "r-3", "r-9"), p)).toEqual(refused(/not live/));
	});

	it("refuses a bundle whose start came after the code's lifetime, whatever the start's verdict (OI-19; BundleEscape023 Esc `startA`)", () => {
		const late = limits.codeLifetime + 1;
		const steps = login();
		const start = steps[2] as Step;
		const lateStart = {
			...start,
			record: { ...start.record, acceptedAt: (steps[1] as Step).record.acceptedAt + late },
		};
		for (const judgment of [
			{ verdict: "held", outcome: "didNotTake" },
			{ verdict: "verified", outcome: "took" },
		] as const) {
			const p = on([...steps.slice(0, 2), { ...lateStart, judgment }]);
			expect(verdictOn(steps[3] as Step, p)).toEqual(refused(/lifetime/));
		}
	});

	it("refuses a second bundle of an exchanged code", () => {
		const p = on([...login(), codeStart(5, "again", "r-2")]);
		expect(verdictOn(codeBundle(6, "again", "r-5", "r-2"), p)).toEqual(refused(/exchanged/));
	});
});

describe("review regressions (D4): a forged start's bundle, a held start's root, J2's count", () => {
	const forgedJ: Finding = { verdict: "forged", outcome: "didNotTake" };

	it("B1: refuses a bundle after a forged start, a forged parent's descendant (J7 不正な親の子孫)", () => {
		const a = on([
			firstKey(1),
			approval(2, "r-1"),
			codeStart(3, "a", "r-2"),
			{ ...codeStart(4, "b", "r-2"), judgment: forgedJ },
		]);
		expect(verdictOn(codeBundle(5, "b", "r-4", "r-2"), a)).toEqual(refused(/forged/));
		const b = on([...login(), { ...refreshStart(5, "rf", "r-4", 7), judgment: forgedJ }]);
		expect(verdictOn(refreshBundle(6, "rf", "r-5", "r-4", 0), b)).toEqual(refused(/forged/));
	});

	it("B2: holds a held start's bundle to the start's root whenever the start's preimage was read (BundleEscape023 NoEscape, W_StaleStartLateBundle)", () => {
		const steps = [firstKey(1), approval(2, "r-1"), approval(3, "r-1", "sid-2")];
		const start = codeStart(4, "login", "r-2");
		const late = {
			...start,
			record: {
				...start.record,
				acceptedAt: (steps[1] as Step).record.acceptedAt + limits.codeLifetime + 500,
			},
			judgment: { verdict: "held", outcome: "didNotTake" } as const,
		};
		const p = on([...steps, late]);
		expect(verdictOn(codeBundle(5, "login", "r-4", "r-3"), p)).toEqual(refused(/roots elsewhere/));
	});

	it("C3: finds no approval, family or key by a name the state's records inherit (toString, __proto__, constructor)", () => {
		for (const name of ["toString", "__proto__", "constructor"]) {
			expect(verdictOn(codeStart(1, "login", name), empty)).toEqual(refused(/not live/));
			expect(verdictOn(refreshStart(1, "rf", name), empty)).toEqual(refused(/not live/));
			expect(verdictOn(approval(2, name), on([firstKey(1)]))).toEqual(refused(/not live/));
			const started = on([firstKey(1), approval(2, "r-1"), codeStart(3, "login", "r-2")]);
			expect(verdictOn(codeBundle(4, "login", "r-3", name), started)).toEqual(
				refused(/roots elsewhere|not live/),
			);
		}
	});

	it("B4: counts code starts alone toward an approval's one exchange, not a refresh start naming it (J2: refresh はここで数えない)", () => {
		const p = on([
			firstKey(1),
			approval(2, "r-1"),
			{ ...refreshStart(3, "rf", "r-2"), judgment: forgedJ },
		]);
		expect(verdictOn(codeStart(4, "login", "r-2"), p)).toEqual(ok);
	});
});

describe("a refresh (Step023 Allowed `ref`: r.fam ∈ S)", () => {
	const loggedIn = () => on(login());

	it("allows a start and a bundle on a live family at its rotation, and the next at the next rotation", () => {
		expect(verdictOn(refreshStart(5, "rf-1", "r-4"), loggedIn())).toEqual(ok);
		const p = on([...login(), refreshStart(5, "rf-1", "r-4")]);
		expect(verdictOn(refreshBundle(6, "rf-1", "r-5", "r-4"), p)).toEqual(ok);
		const rotated = on([
			...login(),
			refreshStart(5, "rf-1", "r-4"),
			refreshBundle(6, "rf-1", "r-5", "r-4"),
		]);
		expect(verdictOn(refreshStart(7, "rf-2", "r-4", 0), rotated)).toEqual(refused(/rotation/));
		expect(verdictOn(refreshStart(7, "rf-2", "r-4", 1), rotated)).toEqual(ok);
	});

	it("refuses a refresh of a family that is not live: abandoned or denied (NoRefreshAfterAbandon)", () => {
		const abandoned = {
			record: coreRecord("abandonment", 5, {
				op: "abandonment:1:login",
				abandons: { op: "login", attempt: 1, digest: "p".repeat(43) },
			}),
			preimage: preimage({}),
		};
		const p = on([...login(), abandoned]);
		expect(p.state.families).toEqual({});
		expect(verdictOn(refreshStart(6, "rf-1", "r-4"), p)).toEqual(refused(/not live/));
	});
});

describe("noEffect and abandonment", () => {
	it("allows noEffect after a stage that did not take, and refuses it after one that took (J7: 「効かなかった」記録と監視者の成否の食い違い)", () => {
		const steps = login();
		const noEffect = {
			record: coreRecord("noEffect", 4, { op: "login", stage: 2 }),
			preimage: preimage({}),
		};
		const didNot = on([
			...steps.slice(0, 2),
			{ ...(steps[2] as Step), judgment: { verdict: "verified", outcome: "didNotTake" } },
		]);
		expect(verdictOn(noEffect, didNot)).toEqual(ok);
		expect(verdictOn(noEffect, on(steps.slice(0, 3)))).toEqual(refused(/took/));
		expect(verdictOn({ ...noEffect, record: { ...noEffect.record, op: "none" } }, didNot)).toEqual(
			refused(/no stage/),
		);
	});

	it("allows an abandonment with no record of its op, and names the family the op's bundle made or rotated (Step023 Allowed `abn`, AbnFam)", () => {
		const abandon = (position: number, op: string) => ({
			record: coreRecord("abandonment", position, {
				op: `abandonment:1:${op}`,
				abandons: { op, attempt: 1, digest: "p".repeat(43) },
			}),
			preimage: preimage({}),
		});
		expect(verdictOn(abandon(1, "nothing"), empty)).toEqual(ok);
		const p = on(login());
		expect(effectOf(askOf(abandon(5, "nothing"), p.state, p.prior))).toEqual({});
		expect(effectOf(askOf(abandon(5, "login"), p.state, p.prior))).toEqual({ abandon: "r-4" });
		const r = on([
			...login(),
			refreshStart(5, "rf-1", "r-4"),
			refreshBundle(6, "rf-1", "r-5", "r-4"),
		]);
		expect(effectOf(askOf(abandon(7, "rf-1"), r.state, r.prior))).toEqual({ abandon: "r-4" });
	});

	it("refuses a kind no Core writer writes", () => {
		const step = { record: coreRecord("denial", 1), preimage: preimage({}) };
		expect(verdictOn(step, empty)).toEqual(refused(/Core writer/));
	});
});

describe("effectOf: a Core record's changes, Eff(r), the same for the Core's intent and the monitor", () => {
	it("gives each kind's changes from its preimage", () => {
		const p = on(login().slice(0, 3));
		const of = (step: Step) => effectOf(askOf(step, p.state, p.prior));
		expect(of(firstKey(1))).toEqual({ key: newKey });
		expect(of(approval(2, "r-1"))).toEqual({
			approval: { key: "r-1", code: digest("code-sid-1"), client: "rp" },
			consume: ["statement:sid-1"],
		});
		expect(of(codeStart(3, "login", "r-2"))).toEqual({});
		expect(of(codeBundle(4, "login", "r-3", "r-2"))).toEqual({
			family: { approval: "r-2" },
			consume: ["code:r-2"],
		});
		expect(of(refreshBundle(6, "rf", "r-5", "r-4"))).toEqual({ rotate: "r-4" });
		expect(of({ record: coreRecord("approval", 2), preimage: { broken: true } })).toEqual({});
	});
});

describe("timely: TimeOK, from the acceptance time (§6.2, A13)", () => {
	const at = (step: Step, p: Prefix, ms: number) => timely(askOf(step, p.state, p.prior), ms);

	it("holds an approval and a first key to their statements' times", () => {
		const t = authorization("sid-1");
		expect(at(approval(2, "r-1"), on([firstKey(1)]), t.iat * 1000)).toBe(true);
		expect(at(approval(2, "r-1"), on([firstKey(1)]), t.exp * 1000 + 1)).toBe(false);
		expect(at(firstKey(1), empty, t.iat * 1000 - 1)).toBe(false);
		expect(at(firstKey(1), empty, t.iat * 1000)).toBe(true);
	});

	it("holds a code's start to its lifetime, a refresh to its family's, a bundle to the issue window", () => {
		const approved = on([firstKey(1), approval(2, "r-1")]);
		const a = (approved.prior[1]?.envelope.acceptedAt ?? 0) as number;
		expect(at(codeStart(3, "login", "r-2"), approved, a + limits.codeLifetime)).toBe(true);
		expect(at(codeStart(3, "login", "r-2"), approved, a + limits.codeLifetime + 1)).toBe(false);
		const started = on(login().slice(0, 3));
		const s = started.prior[2]?.envelope.acceptedAt ?? 0;
		expect(at(codeBundle(4, "login", "r-3", "r-2"), started, s + limits.issueWindow)).toBe(true);
		expect(at(codeBundle(4, "login", "r-3", "r-2"), started, s + limits.issueWindow + 1)).toBe(
			false,
		);
		const loggedIn = on(login());
		const f = loggedIn.state.families["r-4"]?.acceptedAt ?? 0;
		expect(at(refreshStart(5, "rf", "r-4"), loggedIn, f + limits.refreshLifetime)).toBe(true);
		expect(at(refreshStart(5, "rf", "r-4"), loggedIn, f + limits.refreshLifetime + 1)).toBe(false);
	});

	it("holds noEffect and abandonment to no time (they have no time rule)", () => {
		const record = coreRecord("abandonment", 1, {
			op: "abandonment:1:x",
			abandons: { op: "x", attempt: 1, digest: "p".repeat(43) },
		});
		expect(at({ record, preimage: preimage({}) }, empty, 0)).toBe(true);
		expect(checks.digest("x")).toBe(digest("x"));
	});
});
