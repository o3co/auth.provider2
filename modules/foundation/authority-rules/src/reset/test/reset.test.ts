import { instructionSkew } from "@mod/reset-wire";
import { logTyps, opIds } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { checks, context, monitorRecord, sign, T0 } from "../../../test/fixtures/world.ts";
import type { Context } from "../../evidence/evidence.ts";
import { emptyState, fold } from "../../fold/fold.ts";
import { judge } from "../../judgment/judgment.ts";
import { resetFinding } from "../reset.ts";

const id = "A".repeat(22);
const instruction = {
	v: 1,
	installation: "inst-1",
	subject: "sub-1",
	action: "reset",
	kg: 0,
	id,
	iat: T0,
	exp: T0 + 600,
};
const signed = (
	payload: unknown = instruction,
	kid = "reset-1",
	typ: string = logTyps.resetInstruction,
) => sign(payload, kid, typ);
const body = (over: Record<string, unknown> = {}) => ({
	v: 1,
	flow: { of: "subject", id: "sub-1" },
	op: opIds.reset(id),
	prev: 0,
	set: 1,
	instruction: signed(),
	...over,
});
const withReset = (sets: (v: number) => readonly unknown[] | "absent" | undefined): Context => ({
	...context(),
	reset: { installation: "inst-1", sets },
});
const one = withReset((v) => (v === 1 ? [{ kid: "reset-1" }] : "absent"));
const at = T0 * 1000 + 1000;
const find = (b: unknown, c: Context = one, acceptedAt = at, state = emptyState) =>
	resetFinding(b, state, checks, c, acceptedAt);

describe("resetFinding (J0r)", () => {
	it("verifies a reset signed by its version's set, for this installation and the flow's subject, at the key generation before it and within its window, and it takes", () => {
		expect(find(body())).toEqual({ verdict: "verified", outcome: "took" });
	});

	it("holds a reset whose set's version is not yet read, or where no reset context is given", () => {
		expect(
			find(
				body(),
				withReset(() => undefined),
			),
		).toEqual({
			verdict: "held",
			outcome: "didNotTake",
		});
		expect(find(body(), context())).toEqual({ verdict: "held", outcome: "didNotTake" });
	});

	it("names forged, in the rule's order, a shape, a set, a signature, an installation, a subject and an op that do not hold", () => {
		const forged = (reason: string) => ({ verdict: "forged", outcome: "didNotTake", reason });
		expect(find(body({ instruction: "a.b" }))).toEqual(forged("shape"));
		expect(find(body({ instruction: signed({ ...instruction, action: "clear" }) }))).toEqual(
			forged("shape"),
		);
		expect(find(body({ set: 2 }))).toEqual(forged("set"));
		expect(find(body({ instruction: signed(instruction, "stranger") }))).toEqual(
			forged("signature"),
		);
		expect(find(body({ instruction: signed(instruction, "reset-1", "jwt") }))).toEqual(
			forged("signature"),
		);
		expect(find(body({ instruction: signed({ ...instruction, installation: "inst-2" }) }))).toEqual(
			forged("installation"),
		);
		expect(find(body({ flow: { of: "subject", id: "sub-2" } }))).toEqual(forged("subject"));
		expect(find(body({ flow: { of: "client", id: "sub-1" } }))).toEqual(forged("subject"));
		expect(find(body({ op: opIds.reset("B".repeat(22)) }))).toEqual(forged("op"));
		// Padded past reset-wire's limit with whitespace, its payload still the instruction: no CLI carries it.
		const header = signed().split(".")[0];
		const padded = Buffer.from(`{${" ".repeat(9000)}${JSON.stringify(instruction).slice(1)}`);
		const long = `${header}.${padded.toString("base64url")}.reset-1`;
		expect(long.length).toBeGreaterThan(8192);
		expect(find(body({ instruction: long }))).toEqual(forged("shape"));
		// The first that holds is named: a wrong shape before an absent set.
		expect(find(body({ instruction: "a.b", set: 2 }))).toEqual(forged("shape"));
	});

	it("verifies but does not take a reset at another key generation, or accepted outside its window, the skew aside", () => {
		const missed = (reason: string) => ({ verdict: "verified", outcome: "didNotTake", reason });
		expect(find(body(), one, at, { ...emptyState, keyGeneration: 1 })).toEqual(
			missed("generation"),
		);
		const skew = instructionSkew * 1000;
		expect(find(body(), one, T0 * 1000 - skew)).toEqual({ verdict: "verified", outcome: "took" });
		expect(find(body(), one, T0 * 1000 - skew - 1)).toEqual(missed("time"));
		expect(find(body(), one, (T0 + 600) * 1000 + skew)).toEqual({
			verdict: "verified",
			outcome: "took",
		});
		expect(find(body(), one, (T0 + 600) * 1000 + skew + 1)).toEqual(missed("time"));
	});

	it("reads the instruction's payload as the log does: a key named twice is no shape", () => {
		const b64 = (text: string) => Buffer.from(text).toString("base64url");
		const twice = `${b64(JSON.stringify({ alg: "ES256", typ: logTyps.resetInstruction }))}.${b64(
			`${JSON.stringify(instruction).slice(0, -1)},"id":"${"B".repeat(22)}"}`,
		)}.reset-1`;
		expect(find(body({ instruction: twice }))).toEqual({
			verdict: "forged",
			outcome: "didNotTake",
			reason: "shape",
		});
	});
});

describe("a reset boundary judged and folded", () => {
	const record = { ...monitorRecord("resetBoundary", 1), op: opIds.reset(id) };
	const reading = (b: unknown, c: Context = one) => ({
		record,
		body: b,
		state: emptyState,
		prior: [],
		checks,
		context: c,
	});

	it("is found by the reset rule (J0r), its outcome the rule's, and moves the key generation on when it takes", () => {
		const ruling = judge(reading(body()));
		if ("wait" in ruling) throw new Error("waits");
		expect(ruling).toMatchObject({
			row: "J0r",
			counted: false,
			entry: { judgment: { verdict: "verified", outcome: "took" } },
		});
		const { envelope, changes, judgment } = ruling.entry;
		expect(fold(emptyState, envelope, changes, judgment).keyGeneration).toBe(1);
	});

	it("refuses a reset boundary from a writer other than a monitor (J2)", () => {
		for (const role of [
			{ role: "publisher", key: "pub-1" },
			{ role: "human", key: "h-1" },
		]) {
			const ruling = judge({
				...reading(body()),
				record: { ...record, writer: role } as typeof record,
			});
			if ("wait" in ruling) throw new Error("waits");
			expect([ruling.row, ruling.entry.judgment.verdict]).toEqual(["J2", "forged"]);
		}
	});

	it("takes no body naming another flow, op or position than its envelope: the caller's to drop", () => {
		const other = { of: "subject", id: "sub-2" } as const;
		for (const [b, rec] of [
			[body(), { ...record, flow: other }],
			[body({ flow: other, instruction: signed({ ...instruction, subject: "sub-2" }) }), record],
			[body({ prev: 1 }), record],
			[body(), { ...record, op: opIds.reset("B".repeat(22)) }],
		] as const)
			expect(
				() => judge({ ...reading(b), record: rec as typeof record }),
				JSON.stringify(rec.flow),
			).toThrow(TypeError);
	});

	it("names a forged reset's fault, holds one whose set is unread, and moves nothing for either or for one that does not take", () => {
		const other = opIds.reset("B".repeat(22));
		for (const [b, c, verdict, reason] of [
			[body({ op: other }), one, "forged", "op"],
			[body(), withReset(() => undefined), "held", undefined],
			[body({ instruction: signed({ ...instruction, kg: 3 }) }), one, "verified", "generation"],
		] as const) {
			const ruling = judge({ ...reading(b, c), record: { ...record, op: b.op } });
			if ("wait" in ruling) throw new Error("waits");
			expect(ruling.entry.judgment.verdict).toBe(verdict);
			expect(ruling.reason).toBe(reason);
			const { envelope, changes, judgment } = ruling.entry;
			expect(fold(emptyState, envelope, changes, judgment).keyGeneration).toBe(0);
		}
	});
});
