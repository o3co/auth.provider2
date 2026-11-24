import type { Client } from "@mod/clients";
import { type Redeemed, type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import { type Eraser, erasers } from "@mod/erasure-extensions";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { afterEach, expect, it } from "vitest";
import {
	claimScopes,
	claimsSelections,
	type Selection,
	selectionLimits,
	type Target,
	withinLimits,
} from "../src/contract.ts";
import claimsSelectionModule from "../src/module.ts";
import { read, stored } from "../src/stored.ts";
import { claimsSelectionInMemory } from "../src/testing.ts";

let shift = 0;
const runtime = quietRuntime({ clock: { now: () => 1_000_000 + shift } });
let stop = async () => {};
afterEach(async () => {
	shift = 0;
	await stop();
});

const seen = contract<{ hook: RedemptionHook }>("seen");
/** Hands the contributed hook to the test. */
const reader = defineModule(
	{ name: "reader", replicaSafe: false, takes: [redemptionHooks] },
	(m) => [
		m.provide(seen).by(async (c) => {
			const [hook] = await c.collect(redemptionHooks);
			if (!hook) throw new Error("nothing contributed");
			return { hook };
		}),
	],
);
/** A client allowed the scopes in `scopes`, which a test may change. */
const clientAllowed = (scopes: string[]): Client => ({
	id: "app",
	kind: "confidential",
	method: "client_secret_basic",
	registered: true,
	section: <T>() => ({ grants: [], scopes, audiences: [] }) as T,
});

async function serve(
	extra: Module[] = [],
	stores: { readonly module: Module } = claimsSelectionInMemory(),
) {
	const app = await assemble({
		modules: [claimsSelectionModule, stores.module, reader, ...extra],
		config: kernelConfig(),
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	return {
		app,
		stores: stores as ReturnType<typeof claimsSelectionInMemory>,
		selections: app.get(claimsSelections),
		...app.get(seen),
	};
}

const none: Target = { names: [], constraints: [] };
const name = { name: "name", scope: "profile" };
const email = { name: "email", scope: "email" };
const groups = { name: "groups", scope: "groups" };
const asked: Selection = {
	idToken: { names: [email], constraints: [] },
	userinfo: {
		names: [name, groups],
		constraints: [{ name: "email", value: "a@example.com" }],
	},
};
const redeemedOf = (redemption: string, id: string, expiresIn = 600_000) =>
	({
		redemption,
		subject: "alice",
		access: { id, expiresAt: runtime.clock.now() + expiresIn, expiresIn: 600, tokenType: "Bearer" },
	}) as unknown as Redeemed;

it("selects the names whose scope the client is allowed and the approval agreed to, keeping every constraint", async () => {
	const s = await serve();
	const client = clientAllowed(["openid", "profile", "email"]);
	const agreed = { scopes: ["openid", "profile", "groups"], names: [] };
	expect(await s.selections.select(client, "alice", asked, agreed)).toEqual({
		// email is allowed but not agreed to; groups is agreed to but not allowed.
		idToken: none,
		userinfo: { names: [name], constraints: asked.userinfo.constraints },
	});
});

it("takes a name the approval agreed to by name, its scope allowed though not agreed to", async () => {
	const s = await serve();
	const client = clientAllowed(["openid", "email"]);
	const agreed = { scopes: ["openid"], names: ["email", "groups"] };
	expect(await s.selections.select(client, "alice", asked, agreed)).toEqual({
		idToken: { names: [email], constraints: [] },
		userinfo: { names: [], constraints: asked.userinfo.constraints },
	});
});

it("selects no name with nothing agreed to, whatever the client is allowed", async () => {
	const s = await serve();
	const client = clientAllowed(["openid", "profile", "email", "groups"]);
	expect(await s.selections.select(client, "alice", asked, { scopes: [], names: [] })).toEqual({
		idToken: none,
		userinfo: { names: [], constraints: asked.userinfo.constraints },
	});
});

it("refuses a selection past its bounds, or with a value no scalar", async () => {
	const s = await serve();
	const client = clientAllowed(["profile"]);
	const constrained = (constraint: object): Selection => ({
		idToken: none,
		userinfo: {
			names: [],
			constraints: [{ name: "name", ...constraint }] as Target["constraints"],
		},
	});
	const long = "x".repeat(selectionLimits.valueLength);
	expect(
		await s.selections.select(client, "alice", constrained({ value: long }), {
			scopes: [],
			names: [],
		}),
	).toBeDefined();
	for (const past of [
		{ value: `${long}x` },
		{ values: Array.from({ length: selectionLimits.values + 1 }, (_, i) => `v${i}`) },
		{ values: [] },
		{ value: "a", values: ["b"] },
		// Neither: a constraint that names no value would hold back the claim it names whatever it holds.
		{},
		{ essential: true },
		{ value: ["a"] },
		{ value: { a: 1 } },
		{ value: null },
		{ value: Number.POSITIVE_INFINITY },
	]) {
		await expect(
			s.selections.select(client, "alice", constrained(past), { scopes: [], names: [] }),
			JSON.stringify(past),
		).rejects.toThrow(TypeError);
		await expect(s.selections.keepForCode("r", constrained(past), 1000, "alice")).rejects.toThrow(
			TypeError,
		);
	}
	const many: Selection = {
		idToken: none,
		userinfo: {
			names: [],
			constraints: Array.from({ length: 40 }, (_, i) => ({ name: `n${i}`, values: [long] })),
		},
	};
	await expect(
		s.selections.select(client, "alice", many, { scopes: [], names: [] }),
	).rejects.toThrow(TypeError);
});

it("pins a code's selection at its redemption, and answers that pin through the exchange, even past the code's own record", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 10_000, "alice");
	await s.hook.pin("r-1", "alice");
	// The code's record ends at its lifetime and a minute; the pin still answers.
	shift = 10_000 + 60_000;
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	// A code with no selection is pinned as none.
	await s.hook.pin("r-2", "alice");
	expect(await s.selections.forCode("r-2")).toBeUndefined();
	// The pin holds five minutes, not as a deadline: after that, a read fails rather than answer none.
	shift += 300_000;
	await expect(s.selections.forCode("r-1")).rejects.toThrow();
	await expect(s.selections.forCode("r-2")).rejects.toThrow();
	// A redemption never pinned fails the same way.
	await expect(s.selections.forCode("r-3")).rejects.toThrow();
});

it("keeps a code's selection for its lifetime and a minute more, so a code still alive at its pin finds it", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	shift = 600_000 + 59_999;
	await s.hook.pin("r-1", "alice");
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	shift = 600_000 + 60_000;
	await s.hook.pin("r-2", "alice");
	expect(await s.selections.forCode("r-2")).toBeUndefined();
});

it("keeps nothing for a code whose selection holds no name and no constraint, and never a second for one name", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", { idToken: none, userinfo: none }, 600_000, "alice");
	expect(s.stores.names()).toEqual([]);
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	await expect(s.selections.keepForCode("r-2", asked, 600_000, "alice")).rejects.toThrow();
});

it("keeps for a redeemed code's token the pinned userinfo target, until the token's end and two minutes more", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1", 3_600_000));
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 119_999;
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 120_000;
	expect(await s.selections.forToken("tok-1")).toBeUndefined();
	// None for a token whose code had no selection; a redemption whose pin is gone fails.
	await s.hook.pin("r-2", "alice");
	await s.hook.redeemed(redeemedOf("r-2", "tok-2"));
	expect(await s.selections.forToken("tok-2")).toBeUndefined();
	await expect(s.hook.redeemed(redeemedOf("r-3", "tok-3"))).rejects.toThrow();
});

it("fails a read of a record it cannot read as unavailable, never taking it for none", async () => {
	const s = await serve();
	s.stores.overwrite("t.tok-1", { format: 2, target: none });
	s.stores.overwrite("p.r-1", { format: 1, subject: "alice", selection: { idToken: none } });
	const unreadable = { what: "claims-selection: a record it cannot read" };
	await expect(s.selections.forToken("tok-1")).rejects.toMatchObject(unreadable);
	await expect(s.selections.forCode("r-1")).rejects.toMatchObject(unreadable);
	await expect(s.selections.forToken("tok-1")).rejects.toSatisfy(isUnavailable);
});

it("writes every record in format 2, keeping its subject", () => {
	expect(stored.code(asked, "alice")).toEqual({ format: 2, subject: "alice", selection: asked });
	expect(stored.pin(undefined, "alice")).toEqual({ format: 2, subject: "alice" });
	expect(stored.target(none, "alice")).toEqual({ format: 2, subject: "alice", target: none });
	expect(read.code(stored.code(asked, "alice"))).toEqual({ selection: asked, subject: "alice" });
});

/** Records in memory offered through `create`, answering `erased` for a subject in `erased`. */
const fencing = (erased: Set<string>) =>
	claimsSelectionInMemory({
		around: (records) => ({
			read: records.read,
			create: async (name, kept, ms, subject) =>
				erased.has(subject) ? "erased" : records.create(name, kept, ms, subject),
		}),
	});

it("refuses to keep a code's selection for an erased subject, as unavailable, apart from a name kept already", async () => {
	const s = await serve(undefined, fencing(new Set(["erin"])));
	await expect(s.selections.keepForCode("r-1", asked, 600_000, "erin")).rejects.toSatisfy(
		isUnavailable,
	);
	expect(s.stores.names()).toEqual([]);
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	await expect(s.selections.keepForCode("r-2", asked, 600_000, "alice")).rejects.toSatisfy(
		isUnavailable,
	);
});

it("fails every write past its subject's erasure as unavailable", async () => {
	const erased = new Set<string>();
	const s = await serve(undefined, fencing(erased));
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	erased.add("alice");
	await expect(s.hook.pin("r-2", "alice")).rejects.toSatisfy(isUnavailable);
	await expect(s.hook.redeemed(redeemedOf("r-1", "tok-2"))).rejects.toSatisfy(isUnavailable);
});

it("takes a record's own subject, refusing as unavailable a caller's that differs", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await expect(s.hook.pin("r-1", "bob")).rejects.toSatisfy(isUnavailable);
	await s.hook.pin("r-1", "alice");
	await expect(
		s.hook.redeemed({ ...redeemedOf("r-1", "tok-1"), subject: "bob" }),
	).rejects.toSatisfy(isUnavailable);
	// Told no subject, a redemption's differs from its pin's: unavailable, as data, not a caller's bug.
	const untold = { ...redeemedOf("r-1", "tok-1"), subject: undefined } as unknown as Redeemed;
	await expect(s.hook.redeemed(untold)).rejects.toSatisfy(isUnavailable);
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	expect(await s.stores.records.read("t.tok-1")).toMatchObject({ format: 2, subject: "alice" });
});

it("throws a TypeError for a write a caller past the types gives no subject, its bug, writing nothing", async () => {
	const s = await serve();
	const keep = s.selections.keepForCode as (r: string, s: Selection, ms: number) => Promise<void>;
	await expect(keep("r-1", asked, 600_000)).rejects.toThrow(TypeError);
	const pin = s.hook.pin as (redemption: string) => Promise<void>;
	await expect(pin("r-1")).rejects.toThrow(TypeError);
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	await s.hook.pin("r-2", "alice");
	await s.hook.redeemed(redeemedOf("r-2", "tok-1"));
	expect(s.stores.names().filter((n) => !["c.r-2", "p.r-2", "t.tok-1"].includes(n))).toEqual([]);
});

it("refuses to start on a store offering part of erase and migrate", async () => {
	const erase = async () => {
		throw new Error("not called");
	};
	const partial = claimsSelectionInMemory({ around: (records) => ({ ...records, erase }) });
	const refused = await serve(undefined, partial).catch((e: unknown) => e);
	expect(refused).toMatchObject({
		refusals: [expect.objectContaining({ reason: expect.stringContaining("both, or neither") })],
	});
});

it("has no section: a configuration that writes one is refused at boot", async () => {
	const written = assemble({
		modules: [claimsSelectionModule, claimsSelectionInMemory().module],
		config: { ...kernelConfig(), "claims-selection": { mode: "on" } },
		runtime,
	});
	const refused = await written.catch((error: unknown) => error);
	// The refusal names the section, so an operator sees which key to take out.
	expect(BootRefused.is(refused) && refused.refusals).toEqual([
		{ where: "claims-selection", reason: "module without a section" },
	]);
});

/** A table of claim scopes, as the module releasing claims contributes it. */
const scoping = (table: Record<string, string>, name = "scoping") =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(claimScopes).by(() => ({ scopeOf: (claim: string) => table[claim] })),
	]);

it("names a claim's scope as the contributed table does, none without one, and refuses to start with two", async () => {
	const s = await serve([scoping({ name: "profile" })]);
	expect(s.selections.scopeOf("name")).toBe("profile");
	expect(s.selections.scopeOf("email")).toBeUndefined();
	await stop();
	expect((await serve([])).selections.scopeOf("name")).toBeUndefined();
	await stop();
	const twice = serve([scoping({}), scoping({}, "second-scoping")]);
	await expect(twice).rejects.toMatchObject({
		refusals: [expect.objectContaining({ reason: "more than one table of claim scopes" })],
	});
});

it("contributes its eraser, `claims-selection`, not erasable over a store without the ports", async () => {
	const found = contract<readonly Eraser[]>("found-erasers");
	const finder = defineModule({ name: "finder", replicaSafe: false, takes: [erasers] }, (m) => [
		m.provide(found).by((c) => c.collect(erasers)),
	]);
	const s = await serve([finder]);
	const [eraser] = s.app.get(found);
	expect([eraser?.name, eraser?.erasable]).toEqual(["claims-selection", false]);
});

it("offers the bounds check a selection is held to", () => {
	const fits: Selection = {
		idToken: none,
		userinfo: { names: [name], constraints: [{ name: "name", value: "A" }] },
	};
	expect(withinLimits(fits)).toBe(true);
	expect(
		withinLimits({ ...fits, userinfo: { names: [], constraints: [{ name: "name", values: [] }] } }),
	).toBe(false);
});

it("takes all its module names", async () => {
	const stores = claimsSelectionInMemory();
	const input = {
		modules: [claimsSelectionModule, stores.module],
		config: kernelConfig(),
		runtime,
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["claims-selection"]).toBeUndefined();
});

it("pins a redemption once: a second pin for it is unavailable", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await expect(s.hook.pin("r-1", "alice")).rejects.toSatisfy(isUnavailable);
});
