import {
	BootRefused,
	type Contribution,
	defineModule,
	isUnavailable,
	type Module,
	type Parts,
} from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessStandIn } from "@mod/passkey-witness/testing";
import { promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { softwareAuthenticator } from "@mod/webauthn/testing";
import { describe, expect, it } from "vitest";
import {
	heldKeys,
	keyList,
	passkeyGenerations,
	passkeyWitnessing,
	registrations,
} from "../src/contract.ts";
import { memoryWitnessing, world } from "./fixtures/world.ts";

const flow = { of: "subject", id: "s1" } as const;

const contributing = (
	name: string,
	build: (m: Parts<undefined>) => readonly Contribution<undefined>[],
) => defineModule({ name, replicaSafe: true, takes: [] }, build);
const refusalOf = (error: unknown) =>
	BootRefused.is(error) ? error.refusals.map((r) => r.reason).join("\n") : String(error);

const h = (c: string) => c.repeat(43);
const by = (seq: number, statement = h("A"), until = 2_000_000) => ({ statement, seq, until });

async function listed() {
	const w = await world();
	const list = await w.app.get(keyList);
	return { w, list };
}

describe("passkeys, composed", () => {
	const refusedWith = (modules: readonly Module[]) =>
		world({ modules }).then(() => "booted", refusalOf);

	it("requires user verification unless the operator weakens it, which breaks the promise", async () => {
		const w = await world();
		const unverifying = softwareAuthenticator({ userVerified: false });
		const loose = await world({
			section: { "user-verification": "preferred" },
			modules: [promisesModule],
		});
		await loose.register("s1", true, unverifying);
		const login = loose.asserting([], unverifying);
		expect(await loose.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
			userVerified: false,
		});
		const judged = (await loose.app.get(promises)).judgment();
		expect(judged.find((j) => j.promise === "front-compromise-new-authorization")).toMatchObject({
			held: false,
			breaking: [{ by: "passkeys", setting: "passkeys.user-verification" }],
		});
		await expect(w.register("s1", true, unverifying)).rejects.toThrow();
	});

	it("withdraws no mark for state found missing, and reserves no first key beside a mark", async () => {
		const witnessing = memoryWitnessing();
		const w = await world({ modules: [witnessing.module] });
		witnessing.marks.set("s9", 0);
		expect(await w.keys.settle("s9")).toBe(false);
		expect(witnessing.marks.get("s9")).toBe(0);
		const reserved = await w.reserve({ subject: "s9", credential: await w.created(), first: true });
		expect(reserved).toEqual({ refused: "held" });
	});

	it("boots with the key change's writer taking registrations", async () => {
		const w = await world();
		expect(await w.app.get(registrations)).toBe(w.regs);
	});

	it("refuses to boot with two witnessings, or a witness and no witnessing", async () => {
		const witnessing = (name: string) =>
			contributing(name, (m) => [
				m.contribute(passkeyWitnessing).by(() => memoryWitnessing().witnessing),
			]);
		expect(await refusedWith([witnessing("a"), witnessing("b")])).toMatch(
			/more than one passkey witnessing/,
		);
		const witness = contributing("witness", (m) => [
			m.contribute(passkeyWitnesses).by(() => passkeyWitnessStandIn().witness),
		]);
		expect(await refusedWith([witness])).toMatch(/witness is composed without passkey witnessing/);
	});

	it("is taken for registering only by a module that stands on the promises", async () => {
		const silent = defineModule(
			{ name: "silent", replicaSafe: true, takes: [registrations] },
			() => [],
		);
		expect(await refusedWith([silent])).toMatch(/taken only by a module that contributes/);
	});

	it("is taken only by a module that declares where it stands on the promises", async () => {
		const silent = defineModule({ name: "silent", replicaSafe: true, takes: [keyList] }, () => []);
		const refused = await world({ modules: [silent] }).then(
			() => "booted",
			(e: unknown) => (BootRefused.is(e) ? e.refusals.map((r) => r.reason).join("\n") : String(e)),
		);
		expect(refused).toMatch(/taken only by a module that contributes/);
	});

	it("renames an active key of the subject's, its label and time kept through a count moved on", async () => {
		const { w, list } = await listed();
		const { credential } = await w.register("s1");
		const rename = { subject: "s1", credential: credential.id };
		expect(await list.rename({ ...rename, label: "Laptop ✨", by: by(1) })).toBe("renamed");
		const login = w.asserting();
		expect(await w.keys.assert(login.response, { ...login, allow: [] })).toMatchObject({
			kind: "asserted",
		});
		expect(await list.listOf("s1")).toEqual([
			{ credential: credential.id, label: "Laptop ✨", createdAt: 1_000_000 },
		]);
	});

	it("is unavailable, never a refusal, where the credential store cannot tell", async () => {
		const w = await world();
		await w.register();
		w.credentials.fail(true);
		const login = w.asserting();
		const failed = await w.keys.assert(login.response, { ...login, allow: [] }).catch((e) => e);
		expect(isUnavailable(failed)).toBe(true);
		const reserve = await w
			.reserve({ subject: "s1", credential: await w.created() })
			.catch((e) => e);
		expect(isUnavailable(reserve)).toBe(true);
	});
});

describe("passkeyGenerations", () => {
	it("answers a subject's key generation as its applied state holds it, moved on by a boundary taken in", async () => {
		const w = await world();
		const generations = await w.app.get(passkeyGenerations);
		expect(await generations.generation("s1")).toBe(0);
		w.log.boundary(flow);
		// The boundary is on the log, not yet taken in: the applied state lags it.
		expect(await generations.generation("s1")).toBe(0);
		await w.t.tend(flow);
		expect(await generations.generation("s1")).toBe(1);
		expect(await generations.generation("other")).toBe(0);
	});
});

describe("the most keys a subject holds", () => {
	it("is read as full once the subject holds them, and a key more is refused", async () => {
		const w = await world({ section: { "max-credentials": 2 } });
		const held = w.app.get(heldKeys);
		await w.register("s1");
		expect(await held.of("s1")).not.toHaveProperty("full");
		await w.register("s1", false);
		expect(await held.of("s1")).toMatchObject({ full: true });
		await expect(w.register("s1", false)).rejects.toThrow("full");
	});

	it("is at most 16", async () => {
		await expect(world({ section: { "max-credentials": 17 } })).rejects.toThrow();
		await expect(world({ section: { "max-credentials": 16 } })).resolves.toBeDefined();
	});
});
