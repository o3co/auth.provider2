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
import { secretCheckers } from "@mod/secret-hash";
import secretHashModule from "@mod/secret-hash/module";
import { recordingChecker } from "@mod/secret-hash/testing";
import { store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { type Ledger, ledgers, users, usersImport } from "@mod/users";
import usersModule from "@mod/users/module";
import { ledgerContract, memoryUsersStores, testPasswordHash, testUser } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import usersLocal from "../src/module.ts";
import { localRecords, placed } from "../src/records/records.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const seen = contract<{ ledgers: readonly Ledger[]; erasers: readonly Eraser[] }>("seen");
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [ledgers, erasers] },
	(m) => [
		m.provide(seen).by(async (c) => ({
			ledgers: await c.collect(ledgers),
			erasers: await c.collect(erasers),
		})),
	],
);
/** secret-hash's checkers, each recording the work of every computation into `checks`. */
function recordingCheckers(checks: string[]) {
	return defineModule({ name: "secret-hash", replicaSafe: true, takes: [] }, (m) => [
		m.provide(secretCheckers).by(() => ({
			checkerOf: (inUse) => {
				const recording = recordingChecker(inUse, randomBytes);
				const { checker } = recording;
				return {
					check: async (hash, secret) => {
						const before = recording.works.length;
						try {
							return await checker.check(hash, secret);
						} finally {
							checks.push(...recording.works.slice(before));
						}
					},
				};
			},
		})),
	]);
}

const work = testPasswordHash("any secret");

/** users-local over a simulated store in the phase given, with users and the records' builders. */
async function opened(
	phase: "reader" | "indexed" = "indexed",
	options: { checks?: string[]; section?: unknown } = {},
) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	const app = await assemble({
		modules: [
			simulated.module,
			usersLocal,
			options.checks ? recordingCheckers(options.checks) : secretHashModule,
			usersModule,
			memoryUsersStores().module,
			collecting,
		],
		config: {
			...kernelConfig(),
			users: {},
			"users-local": options.section ?? { "password-work": work },
		},
		runtime,
	});
	const [ledger] = app.get(seen).ledgers;
	const eraser = app.get(seen).erasers.find((e) => e.name === "users-local");
	if (!ledger || !eraser) throw new Error("users-local contributed no ledger or eraser");
	const builders = app.get(placed);
	return { app, simulated, ledger, eraser, builders, records: localRecords(builders) };
}

/** Alice, placed as an import would place her: her own subject, and her password's hash. */
async function withAlice(checks?: string[]) {
	const open = await opened("indexed", checks ? { checks } : {});
	expect(await open.records.place("alice", "s-alice", testPasswordHash("correct horse"))).toBe(
		"placed",
	);
	return open;
}

ledgerContract("users-local", {
	open: async () => {
		const checks: string[] = [];
		const { ledger } = await withAlice(checks);
		return { ledger, checks };
	},
	creates: true,
});

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
			const found = await ledger.byIdentifier("carol");
			expect(found).toEqual({
				kind: "user",
				user: first?.kind === "created" ? first.user : undefined,
			});
			expect(Object.isFrozen(found.kind === "user" && found.user)).toBe(true);
		});
	}

	it("makes one subject for an identifier asked twice at once", async () => {
		const { ledger } = await opened();
		const answers = await Promise.all([ledger.create?.("carol"), ledger.create?.("carol")]);
		expect(answers.map((a) => a?.kind).sort()).toEqual(["created", "exists"]);
	});

	it("matches no password for a subject it made, which holds none, after the same work", async () => {
		const checks: string[] = [];
		const { ledger } = await opened("indexed", { checks });
		await ledger.create?.("carol");
		await ledger.verify("carol", "anything");
		const made = [...checks];
		await ledger.verify("nobody", "anything");
		expect(made.length).toBeGreaterThan(0);
		expect(checks.slice(made.length)).toEqual(made);
		expect(await ledger.verify("carol", "")).toEqual({ kind: "none" });
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
			config: { ...kernelConfig(), users: { registered: [testUser("bob", "p")] } },
			runtime,
		}).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals.map((r) => r.where)).toEqual(["users.registered"]);
	});

	it("erases a subject's two records, so its identifier is free for a new subject", async () => {
		const { ledger, eraser } = await opened();
		const made = await ledger.create?.("carol");
		const subject = made?.kind === "created" ? made.user.subject : "";
		expect(eraser.erasable).toBe(true);
		const erased = await eraser.online(subject, signal);
		expect(erased.reports.map((r) => [r.kind, "space" in r && r.space])).toEqual([
			["erased", "users-local.identifiers"],
			["erased", "users-local.subjects"],
		]);
		expect(await ledger.byIdentifier("carol")).toEqual({ kind: "none" });
		expect(await ledger.bySubject(subject)).toEqual({ kind: "none" });
		const again = await ledger.create?.("carol");
		expect(again?.kind === "created" && again.user.subject).not.toBe(subject);
	});

	it("indexes what the reader phase wrote, in the one migration", async () => {
		const reader = await opened("reader");
		await reader.ledger.create?.("carol");
		reader.simulated.mark("subject-records.phase", "indexed");
		const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
			m.provide(store).by(() => reader.app.get(store)),
			m.provide(storeControl).by(() => reader.app.get(storeControl)),
		]);
		const app = await assemble({
			modules: [shared, usersLocal, secretHashModule, collecting],
			config: { ...kernelConfig(), "users-local": {} },
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
			{ kind: "migrated", space: "users-local.subjects", indexed: 1, removed: 0 },
		]);
	});

	it("answers a record of another shape, or a hash it cannot read, unavailable, never none", async () => {
		const { ledger, builders, records } = await opened();
		await builders.identifiers.create("odd", { subject: 7 } as never, "endless", "s-odd");
		await expect(ledger.byIdentifier("odd")).rejects.toSatisfy(isUnavailable);
		await expect(ledger.verify("odd", "p")).rejects.toSatisfy(isUnavailable);
		expect(await records.place("plain", "s-plain", "plain text")).toBe("placed");
		await expect(ledger.verify("plain", "plain text")).rejects.toSatisfy(isUnavailable);
		expect(await ledger.byIdentifier("plain")).toMatchObject({ user: { subject: "s-plain" } });
	});

	it("places nothing for a subject held, answering taken, never exists", async () => {
		const { ledger, records } = await withAlice();
		expect(await records.place("bob", "s-alice")).toBe("taken");
		expect(await ledger.byIdentifier("bob")).toEqual({ kind: "none" });
		expect(await records.place("alice", "s-other")).toBe("exists");
		expect(await ledger.bySubject("s-other")).toEqual({ kind: "none" });
	});

	it("keeps an imported identifier for its subject, again as kept, and answers conflict where either is held otherwise", async () => {
		const { ledger } = await withAlice();
		expect(await ledger.keep?.("s-bob", "bob")).toBe("kept");
		expect(await ledger.keep?.("s-bob", "bob")).toBe("kept");
		expect(await ledger.byIdentifier("bob")).toEqual({
			kind: "user",
			user: { subject: "s-bob", attributes: {} },
		});
		expect(await ledger.keep?.("s-alice", "alice")).toBe("kept");
		expect(await ledger.keep?.("s-mallory", "alice")).toBe("conflict");
		expect(await ledger.keep?.("s-alice", "alice2")).toBe("conflict");
		expect(await ledger.byIdentifier("alice2")).toEqual({ kind: "none" });
		expect(await ledger.bySubject("s-mallory")).toEqual({ kind: "none" });
	});

	it("imports through users' usersImport, the identifier and the verified email", async () => {
		const { app, ledger } = await opened();
		const record = { subject: "s-carol", identifier: "carol", verifiedEmail: "carol@example.com" };
		expect(await app.get(usersImport).record(record)).toBe("imported");
		expect(await ledger.byIdentifier("carol")).toMatchObject({ user: { subject: "s-carol" } });
		expect(await app.get(users).contactsOf("s-carol")).toEqual([
			{ kind: "email", value: "carol@example.com" },
		]);
	});

	it("refuses a password-work that is no hash secret-hash reads", async () => {
		await expect(
			opened("indexed", { section: { "password-work": "plain" } }),
		).rejects.toBeInstanceOf(BootRefused);
		await expect(opened("indexed", { section: {} })).resolves.toBeDefined();
	});
});
