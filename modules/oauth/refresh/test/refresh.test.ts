import { approvals } from "@mod/approvals";
import { claimsSelections } from "@mod/claims-selection";
import { type FamilyMaker, families } from "@mod/code-grant";
import { type Eraser, erasers } from "@mod/erasure-extensions";
import { type Grant, grants } from "@mod/grants";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import { passkeys } from "@mod/passkeys";
import { type Stance, stances } from "@mod/promises";
import { sessions } from "@mod/session";
import { type RevocableKind, revocableKinds } from "@mod/token-revocation";
import { ceremonies } from "@mod/webauthn";
import { afterEach, expect, it } from "vitest";
import { delegation, familyRecords } from "../src/contract.ts";
import refreshModule from "../src/module.ts";
import { familyRecordsInMemory, refreshConfig } from "../src/testing.ts";

let stop = async () => {};
afterEach(() => stop());

const seen = contract<{
	readonly families: readonly FamilyMaker[];
	readonly grants: readonly Grant[];
	readonly kinds: readonly RevocableKind[];
	readonly stances: readonly Stance[];
}>("seen");
const fakes = defineModule(
	{ name: "fakes", replicaSafe: true, takes: [families, grants, revocableKinds, stances] },
	(m) => [
		m.provide(approvals).by(() => ({}) as never),
		m.provide(passkeys).by(() => ({}) as never),
		m.provide(keys).by(() => ({}) as never),
		m.provide(ceremonies).by(() => ({}) as never),
		m.provide(sessions).by(() => ({}) as never),
		m.provide(claimsSelections).by(() => ({}) as never),
		m.provide(seen).by(async (c) => ({
			families: await c.collect(families),
			grants: await c.collect(grants),
			kinds: await c.collect(revocableKinds),
			stances: await c.collect(stances),
		})),
	],
);
const erasersSeen = contract<readonly Eraser[]>("erasers-seen");
const erasing = defineModule({ name: "erasing", replicaSafe: true, takes: [erasers] }, (m) => [
	m.provide(erasersSeen).by((c) => c.collect(erasers)),
]);
const input = (settings = {}) => ({
	modules: [fakes, familyRecordsInMemory().module, refreshModule],
	config: { ...kernelConfig(), ...refreshConfig(settings) },
	runtime: quietRuntime(),
});

it("founds families for code-grant, refreshes them as a grant, revokes them by token, and stands holding a new authorization", async () => {
	const app = await assemble(input());
	await app.start();
	stop = () => app.stop(1000);
	const s = app.get(seen);
	expect(s.families).toHaveLength(1);
	expect(s.grants.map((g) => [g.grantType, g.subjectKind, g.targets])).toEqual([
		["refresh_token", "user", true],
	]);
	expect(s.kinds.map((k) => k.hint)).toEqual(["refresh_token"]);
	expect(s.stances).toEqual([
		{ promise: "front-compromise-new-authorization", holds: true, by: "refresh" },
	]);
});

it("answers the delegation's length from its section: a day unless written, from 5m to 1y", async () => {
	const day = await assemble(input());
	expect(day.get(delegation).lifetimeMs).toBe(86_400_000);
	const hour = await assemble(input({ lifetime: "1h" }));
	expect(hour.get(delegation).lifetimeMs).toBe(3_600_000);
	for (const lifetime of ["4m", "366d", "3600"])
		await expect(assemble(input({ lifetime })), lifetime).rejects.toThrow();
});

it("contributes its eraser, `refresh`, not erasable over a store without the ports, and refuses one offering half of them", async () => {
	const app = await assemble({
		...input(),
		modules: [...input().modules, erasing],
	});
	expect(app.get(erasersSeen).map((e) => [e.name, e.erasable])).toEqual([["refresh", false]]);
	const half = familyRecordsInMemory();
	const halfModule = defineModule(
		{ name: "refresh-records", replicaSafe: false, takes: [] },
		(m) => [
			m.provide(familyRecords).by(() => ({ ...half.records, erase: async () => ({}) as never })),
		],
	);
	await expect(
		assemble({ ...input(), modules: [fakes, halfModule, refreshModule] }),
	).rejects.toMatchObject({
		refusals: [expect.objectContaining({ reason: expect.stringMatching(/both, or neither/) })],
	});
});

it("takes all its module names", async () => {
	expect((await takesUnused(input()))["refresh"]).toBeUndefined();
});
