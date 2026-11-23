import { describe, expect, it } from "vitest";
import {
	assertion,
	authorization,
	checks,
	context,
	origin,
	preimage,
	sign,
	T0,
} from "../../../test/fixtures/world.ts";
import {
	assertedBy,
	contents,
	oneOf,
	readPreimage,
	statementOf,
	statements,
	within,
} from "../evidence.ts";

describe("a Core writer's preimage", () => {
	it("reads the wire's form, then its kind's content, refusing a field neither knows", () => {
		expect(readPreimage("approval", preimage({ parent: "k1" }))).toMatchObject({
			preimage: { parent: "k1" },
			content: {},
		});
		expect(readPreimage("approval", { ...preimage({}), extra: 1 })).toEqual({ error: "preimage" });
		expect(readPreimage("approval", preimage({ content: { extra: 1 } }))).toEqual({
			error: "content",
		});
		expect(readPreimage("start", preimage({ content: { via: "refresh" } }))).toEqual({
			error: "content",
		});
		expect(
			readPreimage("bundle", preimage({ content: { via: "refresh", rotation: 2 } })),
		).toMatchObject({ content: { via: "refresh", rotation: 2 } });
	});

	it("holds a key change to the first-key path alone, its key generation left to the signed creation", () => {
		const first = { variant: "first", credential: "c", publicKey: "pk" };
		expect(contents.keyChange.safeParse(first).success).toBe(true);
		for (const other of [
			{ ...first, variant: "add" },
			{ variant: "remove", key: "k1" },
			{ ...first, keyGeneration: 0 },
		])
			expect(contents.keyChange.safeParse(other).success).toBe(false);
	});

	it("takes one value of a form, none where there are none or several", () => {
		const p = readPreimage(
			"approval",
			preimage({
				evidence: [
					{ form: "statement", value: "s" },
					{ form: "assertion", value: "a1" },
					{ form: "assertion", value: "a2" },
				],
			}),
		);
		if ("error" in p) throw new Error("unread");
		expect(oneOf(p.preimage, "statement")).toBe("s");
		expect(oneOf(p.preimage, "assertion")).toBeUndefined();
		expect(oneOf(p.preimage, "jar")).toBeUndefined();
	});
});

describe("statements and assertions (J7: the writer generation's ring, OI-22)", () => {
	const t = authorization("sid-1");
	it("reads a statement signed by the writer generation's ring as a statement, and no other", () => {
		expect(statementOf(sign(t, "ring-1"), statements.authorization, checks, context(1))).toEqual(t);
		expect(
			statementOf(sign(t, "ring-1"), statements.authorization, checks, context(2)),
		).toBeUndefined();
		expect(
			statementOf(sign(t, "ring-1", "jwt"), statements.authorization, checks, context(1)),
		).toBeUndefined();
		expect(
			statementOf(sign({ ...t, extra: 1 }, "ring-1"), statements.authorization, checks, context(1)),
		).toBeUndefined();
	});

	it("takes an assertion made by the key over the statement's challenge for the origin", () => {
		const key = { credential: "c1", publicKey: "pk1" };
		const s = sign(t, "ring-1");
		expect(assertedBy(assertion(key, s), key, s, checks, context())).toBe(true);
		expect(assertedBy(assertion(key, "other"), key, s, checks, context())).toBe(false);
		expect(assertedBy(assertion(key, s, "https://evil"), key, s, checks, context())).toBe(false);
		expect(assertedBy(assertion({ ...key, credential: "c2" }, s), key, s, checks, context())).toBe(
			false,
		);
		expect(origin).toBe(context().origin);
	});

	it("holds a statement's times around the acceptance time, in seconds against ms", () => {
		const times = { iat: T0, exp: T0 + 300 };
		expect(within(times, T0 * 1000)).toBe(true);
		expect(within(times, (T0 + 300) * 1000)).toBe(true);
		expect(within(times, T0 * 1000 - 1)).toBe(false);
		expect(within(times, (T0 + 300) * 1000 + 1)).toBe(false);
	});
});
