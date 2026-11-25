import { randomBytes } from "node:crypto";
import { type Eraser, erasers, type Walk } from "@mod/erasure-extensions";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type PasskeyWitness, passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessContract } from "@mod/passkey-witness/testing";
import { promiseNames, promises } from "@mod/promises";
import promisesModule from "@mod/promises/module";
import { secretCheckers } from "@mod/secret-hash";
import secretHashModule from "@mod/secret-hash/module";
import { recordingChecker, testScryptHash } from "@mod/secret-hash/testing";
import { store, storeControl } from "@mod/store";
import storeModule from "@mod/store/module";
import { simulatedStore, storeConfig } from "@mod/store/testing";
import { type Ledger, ledgers, users, usersImport } from "@mod/users";
import usersModule from "@mod/users/module";
import {
	identifierlessKeyOf,
	ledgerContract,
	memoryUsersStores,
	testUser,
} from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import usersLocal from "../src/module.ts";
import { localRecords, placed } from "../src/records/records.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
/** The passwords' work, the cheapest scrypt: a hash of it as `testScryptHash` makes one. */
const work = "scrypt:10,8,1,32,16";
const localConfig = { "users-local": { "password-work": work } };
/** secret-hash's checkers, the work of every computation each check makes recorded, in order, in `checks`. */
const recordingCheckers = (checks: string[]) =>
	defineModule({ name: "secret-hash", replicaSafe: true, takes: [] }, (m) => [
		m.provide(secretCheckers).by(() => ({
			checkerOf: (inUse) => {
				const made = recordingChecker(inUse, randomBytes);
				return {
					check: async (hash, secret) => {
						const before = made.works.length;
						const matched = await made.checker.check(hash, secret);
						checks.push(...made.works.slice(before));
						return matched;
					},
				};
			},
		})),
	]);
const seen = contract<{
	ledgers: readonly Ledger[];
	erasers: readonly Eraser[];
	witnesses: readonly PasskeyWitness[];
}>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [ledgers, erasers, passkeyWitnesses] },
	(m) => [
		m.provide(seen).by(async (c) => ({
			ledgers: await c.collect(ledgers),
			erasers: await c.collect(erasers),
			witnesses: await c.collect(passkeyWitnesses),
		})),
	],
);
/** users-local over a simulated store in the phase given, with users and the records' builders; every password computation's work in `checks`. */
async function opened(phase: "reader" | "indexed" = "indexed") {
	const checks: string[] = [];
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [
			simulated.module,
			usersLocal,
			recordingCheckers(checks),
			usersModule,
			memoryUsersStores().module,
			collecting,
		],
		config: { ...kernelConfig(), ...localConfig, users: {} },
		runtime,
	});
	const [ledger] = app.get(seen).ledgers;
	const [witness, ...more] = app.get(seen).witnesses;
	const eraser = app.get(seen).erasers.find((e) => e.name === "users-local");
	if (!ledger || !eraser || !witness || more.length > 0)
		throw new Error("users-local contributed no ledger, eraser or one witness");
	const builders = app.get(placed);
	return {
		app,
		simulated,
		ledger,
		witness,
		eraser,
		builders,
		records: localRecords(builders),
		checks,
	};
}

/** Alice, placed as an import would place her: her own subject. */
async function withAlice() {
	const open = await opened();
	expect(await open.records.place("alice", "s-alice")).toBe("placed");
	return open;
}

for (const phase of ["reader", "indexed"] as const) {
	ledgerContract(`users-local, ${phase}`, {
		open: async () => {
			const open = await opened(phase);
			const hash = testScryptHash("correct horse");
			expect(await open.ledger.keep?.("s-alice", "alice", hash)).toBe("kept");
			return { ledger: open.ledger, checks: open.checks };
		},
		creates: true,
		createsIdentifierless: true,
	});
}

for (const phase of ["reader", "indexed"] as const) {
	passkeyWitnessContract(
		`users-local's witness, ${phase}`,
		async () => (await opened(phase)).witness,
	);
}

const signal = new AbortController().signal;

describe("users-local", () => {
	for (const phase of ["reader", "indexed"] as const) {
		it(`makes a drawn subject for each new identifier, and answers exists for one held, ${phase}`, async () => {
			const { ledger } = await opened(phase);
			const first = await ledger.create?.("carol");
			const second = await ledger.create?.("dave");
			expect(first?.kind === "created" && first.user.subject).toMatch(/^[0-9a-f]{32}$/);
			expect(first?.kind === "created" && second?.kind === "created").toBe(true);
			expect(first).not.toEqual(second);
			expect(await ledger.create?.("carol")).toEqual({ kind: "exists" });
			const found = await ledger.byIdentifier?.("carol");
			expect(found).toEqual({
				kind: "user",
				user: first?.kind === "created" ? first.user : undefined,
			});
			expect(Object.isFrozen(found?.kind === "user" && found.user)).toBe(true);
		});
	}

	it("makes one subject for an identifier asked twice at once", async () => {
		const { ledger } = await opened();
		const answers = await Promise.all([ledger.create?.("carol"), ledger.create?.("carol")]);
		expect(answers.map((a) => a?.kind).sort()).toEqual(["created", "exists"]);
	});

	it("finds a user by identifier and by subject, exactly, and none for one it does not hold", async () => {
		const { ledger } = await withAlice();
		const alice = { kind: "user", user: { subject: "s-alice", attributes: {} } };
		expect(await ledger.byIdentifier?.("alice")).toEqual(alice);
		expect(await ledger.bySubject("s-alice")).toEqual(alice);
		for (const other of ["Alice", "alice ", "nobody"]) {
			expect(await ledger.byIdentifier?.(other), other).toEqual({ kind: "none" });
		}
		expect(await ledger.bySubject("alice")).toEqual({ kind: "none" });
	});

	it("declares its passwords by password-work, and refuses to start without one secret-hash reads", async () => {
		const { ledger } = await opened();
		expect(ledger.passwords).toEqual({ work });
		for (const section of [{}, { "password-work": "scrypt:9,8,1,32,16" }, { "password-work": 7 }]) {
			const refused = await assemble({
				modules: [simulatedStore().module, usersLocal, secretHashModule],
				config: { ...kernelConfig(), "users-local": section },
				runtime,
			}).catch((error: unknown) => error);
			expect(refused, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
				"users-local.password-work",
			]);
		}
	});

	it("keeps a password's hash with its identifier, again as kept, and answers conflict for another hash or none", async () => {
		const { ledger } = await withAlice();
		const hash = testScryptHash("correct horse");
		expect(await ledger.keep?.("s-bob", "bob", hash)).toBe("kept");
		expect(await ledger.keep?.("s-bob", "bob", hash)).toBe("kept");
		expect(await ledger.verify("bob", "correct horse")).toMatchObject({
			user: { subject: "s-bob" },
		});
		expect(await ledger.keep?.("s-bob", "bob", testScryptHash("correct horse"))).toBe("conflict");
		expect(await ledger.keep?.("s-bob", "bob")).toBe("conflict");
		// Alice is held with no password: one brought for her later is held otherwise.
		expect(await ledger.keep?.("s-alice", "alice", hash)).toBe("conflict");
		expect(await ledger.verify("alice", "correct horse")).toEqual({ kind: "none" });
	});

	it("reads one record and computes the work once for an identifier held with a hash, held with none, or not held", async () => {
		const { ledger, builders, checks } = await withAlice();
		expect(await ledger.keep?.("s-bob", "bob", testScryptHash("correct horse"))).toBe("kept");
		const read = builders.identifiers.read;
		const reads: string[] = [];
		Object.assign(builders.identifiers, {
			read: (key: string) => {
				reads.push(key);
				return read(key);
			},
		});
		for (const identifier of ["bob", "alice", "nobody"]) {
			const [readsBefore, checksBefore] = [reads.length, checks.length];
			expect(await ledger.verify(identifier, "wrong"), identifier).toEqual({ kind: "none" });
			expect(reads.slice(readsBefore), identifier).toEqual([identifier]);
			expect(checks.slice(checksBefore), identifier).toEqual([work]);
		}
	});

	it("takes no hash of another work, and answers a check meeting one held unavailable", async () => {
		const { ledger, records } = await opened();
		const other = testScryptHash("correct horse", 11);
		await expect(ledger.keep?.("s-bob", "bob", other)).rejects.toThrow(TypeError);
		expect(await ledger.byIdentifier?.("bob")).toEqual({ kind: "none" });
		// One written before the work changed.
		expect(await records.place("carol", "s-carol", other)).toBe("placed");
		// And one it cannot read as a hash at all.
		expect(await records.place("dave", "s-dave", "not a hash")).toBe("placed");
		for (const identifier of ["carol", "dave"]) {
			const refused = await ledger
				.verify(identifier, "correct horse")
				.catch((error: unknown) => error);
			expect(isUnavailable(refused), identifier).toBe(true);
		}
	});

	it("users offers create through it, and refuses to start beside users in the settings", async () => {
		const { app } = await opened();
		const made = await app.get(users).create?.("carol");
		expect(made?.kind).toBe("created");
		const simulated = simulatedStore();
		const error = await assemble({
			modules: [
				simulated.module,
				usersLocal,
				secretHashModule,
				usersModule,
				memoryUsersStores().module,
			],
			config: { ...kernelConfig(), ...localConfig, users: { registered: [testUser("bob", "p")] } },
			runtime,
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals.map((r) => r.where)).toEqual(["users.registered"]);
	});

	it("erases a subject's two records and its witness's mark, so its identifier is free for a new subject", async () => {
		const { ledger, witness, eraser } = await opened();
		const made = await ledger.create?.("carol");
		const subject = made?.kind === "created" ? made.user.subject : "";
		expect(await witness.enroll(subject, "t")).toBe(true);
		expect(eraser.erasable).toBe(true);
		const erased = await eraser.online(subject, signal);
		expect(erased.reports.map((r) => [r.kind, "space" in r && r.space])).toEqual([
			["erased", "users-local.identifiers"],
			["erased", "users-local.identifierless"],
			["erased", "users-local.subjects"],
			["erased", "users-local.marks"],
		]);
		expect(await ledger.byIdentifier?.("carol")).toEqual({ kind: "none" });
		expect(await ledger.bySubject(subject)).toEqual({ kind: "none" });
		expect(await witness.read(subject)).toBe(false);
		// No mark is set past the subject's erasure: unavailable, never another's.
		await expect(witness.enroll(subject, "t")).rejects.toSatisfy(isUnavailable);
		const again = await ledger.create?.("carol");
		expect(again?.kind === "created" && again.user.subject).not.toBe(subject);
	});

	it("erases an identifierless subject's key with its record, so the key makes a new subject after", async () => {
		const { ledger, eraser } = await opened();
		const key = identifierlessKeyOf("erin");
		const made = await ledger.createIdentifierless?.(key);
		const subject = made?.subject ?? "";
		expect(await ledger.bySubject(subject)).toEqual({ kind: "user", user: made });
		const erased = await eraser.online(subject, signal);
		expect(erased.reports.map((r) => [r.kind, "space" in r && r.space])).toEqual([
			["erased", "users-local.identifiers"],
			["erased", "users-local.identifierless"],
			["erased", "users-local.subjects"],
			["erased", "users-local.marks"],
		]);
		expect(await ledger.bySubject(subject)).toEqual({ kind: "none" });
		expect((await ledger.createIdentifierless?.(key))?.subject).not.toBe(subject);
	});

	it("indexes what the reader phase wrote, in the one migration", async () => {
		const reader = await opened("reader");
		const made = await reader.ledger.create?.("carol");
		await reader.witness.enroll(made?.kind === "created" ? made.user.subject : "", "t");
		const dave = identifierlessKeyOf("dave");
		const unindexed = await reader.ledger.createIdentifierless?.(dave);
		reader.simulated.mark("subject-records.phase", "indexed");
		const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
			m.provide(store).by(() => reader.app.get(store)),
			m.provide(storeControl).by(() => reader.app.get(storeControl)),
		]);
		const app = await assemble({
			modules: [shared, usersLocal, secretHashModule, collecting],
			config: { ...kernelConfig(), ...localConfig },
			runtime,
		});
		const eraser = app.get(seen).erasers.find((e) => e.name === "users-local");
		const inner = reader.app.get(store);
		const walk: Walk = {
			sweep: async (space, cursor) => {
				const page = await inner.scan(reader.simulated.declaredSpace(space), cursor);
				return page.cursor === undefined
					? { keys: page.keys, server: "one" }
					: { keys: page.keys, cursor: page.cursor, server: "one" };
			},
		};
		expect(await eraser?.migrate(walk, signal)).toEqual([
			{ kind: "migrated", space: "users-local.identifiers", indexed: 1, removed: 0 },
			{ kind: "migrated", space: "users-local.identifierless", indexed: 1, removed: 0 },
			{ kind: "migrated", space: "users-local.subjects", indexed: 2, removed: 0 },
			{ kind: "migrated", space: "users-local.marks", indexed: 1, removed: 0 },
		]);
		// The identifierless subject the reader phase wrote is erased by its index now, its key with it.
		const ledger = app.get(seen).ledgers[0];
		const subject = unindexed?.subject ?? "";
		await eraser?.online(subject, signal);
		expect(await ledger?.bySubject(subject)).toEqual({ kind: "none" });
		expect((await ledger?.createIdentifierless?.(dave))?.subject).not.toBe(subject);
	});

	it("answers a record of another shape unavailable, never none", async () => {
		const { ledger, builders } = await opened();
		await builders.identifiers.create("odd", { subject: 7 } as never, "endless", "s-odd");
		await expect(ledger.byIdentifier?.("odd")).rejects.toSatisfy(isUnavailable);
		await builders.subjects.create("s-odd", { identifier: [] } as never, "endless", "s-odd");
		await expect(ledger.bySubject("s-odd")).rejects.toSatisfy(isUnavailable);
	});

	it("answers a mark of another shape unavailable, never marked or unmarked", async () => {
		const { witness, builders } = await opened();
		await builders.marks.create("s-odd", { token: "" } as never, "endless", "s-odd");
		await expect(witness.read("s-odd")).rejects.toSatisfy(isUnavailable);
		await expect(witness.markedWith("s-odd")).rejects.toSatisfy(isUnavailable);
		await expect(witness.enroll("s-odd", "t")).rejects.toSatisfy(isUnavailable);
	});

	it("stands breaking store-write: its witness's marks are in the Core's store beside the passkeys", async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, usersLocal, secretHashModule, promisesModule],
			config: { ...kernelConfig(), ...localConfig },
			runtime,
		});
		const judged = app
			.get(promises)
			.judgment()
			.find((j) => j.promise === promiseNames.storeWrite);
		expect(judged?.held).toBe(false);
		expect(judged?.breaking).toContainEqual({
			by: "users-local",
			reason: expect.stringContaining("passkey witness"),
		});
		const refused = await assemble({
			modules: [simulatedStore().module, usersLocal, secretHashModule, promisesModule],
			config: {
				...kernelConfig(),
				...localConfig,
				promises: { required: [promiseNames.storeWrite] },
			},
			runtime,
		}).catch((e: unknown) => e);
		expect(BootRefused.is(refused)).toBe(true);
	});

	it("places nothing for a subject held, answering taken, never exists", async () => {
		const { ledger, records } = await withAlice();
		expect(await records.place("bob", "s-alice")).toBe("taken");
		expect(await ledger.byIdentifier?.("bob")).toEqual({ kind: "none" });
		expect(await records.place("alice", "s-other")).toBe("exists");
		expect(await ledger.bySubject("s-other")).toEqual({ kind: "none" });
	});

	it("keeps an imported identifier for its subject, again as kept, and answers conflict where either is held otherwise", async () => {
		const { ledger } = await withAlice();
		expect(await ledger.keep?.("s-bob", "bob")).toBe("kept");
		expect(await ledger.keep?.("s-bob", "bob")).toBe("kept");
		expect(await ledger.byIdentifier?.("bob")).toEqual({
			kind: "user",
			user: { subject: "s-bob", attributes: {} },
		});
		expect(await ledger.keep?.("s-alice", "alice")).toBe("kept");
		expect(await ledger.keep?.("s-mallory", "alice")).toBe("conflict");
		expect(await ledger.keep?.("s-alice", "alice2")).toBe("conflict");
		expect(await ledger.byIdentifier?.("alice2")).toEqual({ kind: "none" });
		expect(await ledger.bySubject("s-mallory")).toEqual({ kind: "none" });
	});

	it("imports through users' usersImport, the identifier, its password's hash and the verified email", async () => {
		const { app, ledger } = await opened();
		const record = {
			subject: "s-carol",
			identifier: "carol",
			passwordHash: testScryptHash("correct horse"),
			verifiedEmail: "carol@example.com",
		};
		expect(await app.get(usersImport).record(record)).toBe("imported");
		expect(await ledger.byIdentifier?.("carol")).toMatchObject({ user: { subject: "s-carol" } });
		expect(await app.get(users).verify("carol", "correct horse")).toMatchObject({
			user: { subject: "s-carol" },
		});
		expect(await app.get(users).contactsOf("s-carol")).toEqual([
			{ kind: "email", value: "carol@example.com" },
		]);
	});

	it("keeps an identifier for an erased subject as a conflict, and makes no subject for it", async () => {
		const { ledger, eraser } = await withAlice();
		await eraser.online("s-alice", signal);
		expect(await ledger.keep?.("s-alice", "alice-again")).toBe("conflict");
		expect(await ledger.byIdentifier?.("alice-again")).toEqual({ kind: "none" });
	});

	it("declares both spaces authenticated: over the memory store it boots only as the store's setting accepts", async () => {
		const simulated = simulatedStore();
		await assemble({
			modules: [simulated.module, usersLocal, secretHashModule],
			config: { ...kernelConfig(), ...localConfig },
			runtime,
		});
		for (const space of ["users-local.identifiers", "users-local.subjects", "users-local.marks"]) {
			expect(simulated.declaredSpace(space).guarantees, space).toContain("authenticated");
		}
		const over = (accept: boolean) =>
			assemble({
				modules: [storeModule, usersLocal, secretHashModule],
				config: {
					...kernelConfig(),
					...localConfig,
					...storeConfig({ "accept-unauthenticated": accept }),
				},
				runtime,
			});
		await expect(over(false)).rejects.toBeInstanceOf(BootRefused);
		await expect(over(true)).resolves.toBeDefined();
	});
});
