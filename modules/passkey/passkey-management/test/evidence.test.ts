import { BootRefused, defineModule, Unavailable } from "@mod/kernel";
import { evidence, evidenceKinds, trustedNames } from "@mod/promises";
import { describe, expect, it } from "vitest";
import { type EvidenceAnswer, type FirstKeyEvidence, firstKeyEvidence } from "../src/contract.ts";
import { evidenceOver, itemsOf } from "../src/evidence/evidence.ts";
import { composed } from "./fixtures/composed.ts";

const start = { nonce: "n", identifier: "alice" };

/** A kind answering as told, recording the items it was given and the ends it was told. */
function kindAnswering(kind: string, answer: EvidenceAnswer["kind"] | "throws") {
	const given: unknown[] = [];
	const told: string[] = [];
	const evidence: FirstKeyEvidence = {
		kind,
		check: async (_, __, items) => {
			given.push(items);
			if (answer === "throws") throw new Unavailable("kind");
			return { kind: answer };
		},
		settled: async (_, __, outcome) => {
			told.push(outcome);
			if (kind === "loud") throw new Error("a kind's end that throws");
		},
	};
	return { evidence, given, told };
}

describe("the path's rule over the kinds composed", () => {
	const asked = async (answers: (EvidenceAnswer["kind"] | "throws")[], inboxOnly = false) => {
		const kinds = answers.map((a, i) => kindAnswering(`k${i}`, a));
		const result = await evidenceOver(
			kinds.map((k) => k.evidence),
			inboxOnly,
		).ask(start, "s-alice", {});
		return { result, kinds };
	};

	it("passes on the inbox alone where no kind is composed", async () => {
		expect((await asked([])).result.checked).toBe("passed");
	});

	it("passes where every kind not absent passed, and fails where one failed", async () => {
		expect((await asked(["passed", "absent"])).result.checked).toBe("passed");
		expect((await asked(["passed", "failed", "absent"])).result.checked).toBe("failed");
	});

	it("refuses one absent on every kind, unless the inbox alone is let pass then", async () => {
		expect((await asked(["absent", "absent"])).result.checked).toBe("failed");
		expect((await asked(["absent", "absent"], true)).result.checked).toBe("passed");
	});

	it("asks every kind whatever another answered, and comes to unavailable on a fault", async () => {
		const { result, kinds } = await asked(["throws", "failed", "passed"]);
		expect(result.checked).toBe("unavailable");
		expect(result.faults).toHaveLength(1);
		expect(kinds.every((k) => k.given.length === 1)).toBe(true);
	});

	it("tells every kind the start's end once, one that throws let be", async () => {
		const loud = kindAnswering("loud", "passed");
		const quiet = kindAnswering("quiet", "passed");
		const result = await evidenceOver([loud.evidence, quiet.evidence], false).ask(
			start,
			"s-alice",
			{},
		);
		expect(await result.tell("failed")).toHaveLength(1);
		expect([loud.told, quiet.told]).toEqual([["failed"], ["failed"]]);
	});

	it("takes an answer of no word it knows as the kind's fault, never a pass, asking the rest", async () => {
		const odd = (answer: unknown): FirstKeyEvidence => ({
			kind: "odd",
			check: async () => answer as EvidenceAnswer,
		});
		for (const answer of [{}, { kind: "ok" }, { kind: undefined }, null]) {
			const after = kindAnswering("after", "passed");
			const result = await evidenceOver([odd(answer), after.evidence], false).ask(
				start,
				"s-alice",
				{},
			);
			expect(result.checked, JSON.stringify(answer)).toBe("unavailable");
			expect(result.faults[0]).toBeInstanceOf(TypeError);
			expect(after.given).toHaveLength(1);
		}
	});

	it("comes to unavailable on a fault beside kinds absent, the inbox alone let pass or not", async () => {
		expect((await asked(["throws", "absent"])).result.checked).toBe("unavailable");
		expect((await asked(["throws", "absent"], true)).result.checked).toBe("unavailable");
	});

	it("answers each fault as thrown, and asks each kind with the subject as given, none too", async () => {
		const seen: (string | undefined)[] = [];
		const thrown = new Unavailable("kind");
		const kind: FirstKeyEvidence = {
			kind: "k",
			check: async (_, subject) => {
				seen.push(subject);
				throw thrown;
			},
		};
		const result = await evidenceOver([kind], false).ask(start, undefined, {});
		expect(result.faults).toEqual([thrown]);
		expect(result.faults[0]).toBe(thrown);
		expect(seen).toEqual([undefined]);
	});

	it("tells each kind once however often told, one whose check threw too, and one throwing at once lets the rest be told", async () => {
		const failing = kindAnswering("failing", "throws");
		const quiet = kindAnswering("quiet", "passed");
		const told: string[] = [];
		const sudden: FirstKeyEvidence = {
			kind: "sudden",
			check: async () => ({ kind: "passed" }),
			settled: (() => {
				told.push("sudden");
				throw new Error("thrown at once");
			}) as never,
		};
		const result = await evidenceOver([sudden, failing.evidence, quiet.evidence], false).ask(
			start,
			"s-alice",
			{},
		);
		const [first, second] = await Promise.all([result.tell("unavailable"), result.tell("passed")]);
		await result.tell("failed");
		expect(first).toBe(second);
		expect(first).toHaveLength(1);
		expect([told, failing.told, quiet.told]).toEqual([
			["sudden"],
			["unavailable"],
			["unavailable"],
		]);
	});

	it("hands each kind its own items alone, none from the prototype", async () => {
		const password = kindAnswering("password", "passed");
		const other = kindAnswering("toString", "passed");
		await evidenceOver([password.evidence, other.evidence], false).ask(
			start,
			"s-alice",
			itemsOf({ password: "pw" }),
		);
		expect(password.given).toEqual([{ password: "pw" }]);
		expect(other.given).toEqual([undefined]);
		expect(itemsOf({})).toEqual({});
	});
});

const declaring = (name: string, past?: true) =>
	defineModule({ name: `${name}-kind`, replicaSafe: true, takes: [] }, (m) => [
		m.contribute(firstKeyEvidence).by(() => kindAnswering(name, "passed").evidence),
		m.contribute(evidenceKinds).by(() => ({
			kind: name,
			by: `${name}-kind`,
			trusts: [trustedNames.password],
			strength: { kind: "guesses", guesses: { count: 5, windowMs: 1000 } },
			...(past ? { past } : {}),
		})),
	]);
const composing = (settings = {}, ...modules: ReturnType<typeof defineModule>[]) =>
	composed({ settings, modules }).then((made) => made.app);

describe("the inbox declared, and the kinds composed checked against what promises holds", () => {
	it("declares the inbox alone where no kind is composed, or one absent on all may pass", async () => {
		const kindsOf = async (settings = {}, ...modules: ReturnType<typeof defineModule>[]) =>
			(await composing(settings, ...modules)).get(evidence).kinds();
		const inbox = {
			kind: "inbox",
			by: "passkey-management",
			trusts: ["inbox"],
			strength: { kind: "secret", bits: 256, lifetimeMs: 900_000 },
		};
		expect(await kindsOf()).toEqual([{ ...inbox, alone: true }]);
		expect((await kindsOf({}, declaring("password"))).find((k) => k.kind === "inbox")).toEqual(
			inbox,
		);
		const on = await kindsOf({ "inbox-only-when-absent": true }, declaring("password"));
		expect(on.find((k) => k.kind === "inbox")).toEqual({ ...inbox, alone: true });
	});

	it("refuses boot for a kind composed that promises holds as past, or holds no declaration of", async () => {
		const undeclaredKind = defineModule({ name: "bare", replicaSafe: true, takes: [] }, (m) => [
			m.contribute(firstKeyEvidence).by(() => kindAnswering("bare", "passed").evidence),
		]);
		for (const kind of [declaring("old", true), undeclaredKind]) {
			const refused = await composing({}, kind).catch((error: unknown) => error);
			expect(BootRefused.is(refused)).toBe(true);
			expect((refused as BootRefused).refusals[0]?.where).toBe("passkey-management");
		}
	});
});
