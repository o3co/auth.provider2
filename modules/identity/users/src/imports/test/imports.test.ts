import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { testScryptHash } from "@mod/secret-hash/testing";
import { describe, expect, it } from "vitest";
import {
	type ContactStore,
	contactStore,
	type Ledger,
	ledgers,
	users,
	usersImport,
	type Verified,
} from "../../contract.ts";
import usersModule from "../../module.ts";
import { memoryUsersStores, testUser } from "../../testing.ts";

const none: Verified = { kind: "none" };

/** A ledger that takes imports, holding each identifier for one subject. */
function keepingLedger(held = new Map<string, string>()): Ledger {
	return {
		verify: async () => none,
		bySubject: async () => none,
		byIdentifier: async () => none,
		keep: async (subject, identifier) => {
			const holder = held.get(identifier);
			if (holder !== undefined) return holder === subject ? "kept" : "conflict";
			held.set(identifier, subject);
			return "kept";
		},
	};
}

async function opened(
	ledger?: Ledger,
	registered: unknown[] = [],
	stores = memoryUsersStores().module,
) {
	const contributing = ledger
		? [
				defineModule({ name: "a-ledger", replicaSafe: true, takes: [] }, (m) => [
					m.contribute(ledgers).by(() => ledger),
				]),
			]
		: [];
	const app = await assemble({
		modules: [usersModule, secretHashModule, stores, ...contributing],
		config: { ...kernelConfig(), users: { registered } },
	});
	return { importer: app.get(usersImport), u: app.get(users) };
}

describe("users' import", () => {
	it("keeps a subject's identifier through the ledger and its verified email as a verified contact", async () => {
		const held = new Map<string, string>();
		const { importer, u } = await opened(keepingLedger(held));
		const record = { subject: "s-alice", identifier: "alice", verifiedEmail: "alice@example.com" };
		expect(await importer.record(record)).toBe("imported");
		expect(held.get("alice")).toBe("s-alice");
		expect(await u.contactsOf("s-alice")).toEqual([{ kind: "email", value: "alice@example.com" }]);
		// Again, as a run done twice: held as given, so imported, and kept once.
		expect(await importer.record(record)).toBe("imported");
		expect(await u.contactsOf("s-alice")).toHaveLength(1);
		expect(await importer.record({ subject: "s-bob" })).toBe("imported");
	});

	it("keeps a password's hash with the identifier where the ledger holds passwords, and none where it holds none", async () => {
		const hash = testScryptHash("correct horse");
		const kept: (string | undefined)[] = [];
		const ledger = keepingLedger();
		const holding: Ledger = {
			...ledger,
			passwords: { work: "scrypt:10,8,1,32,16" },
			keep: async (s, i, passwordHash) => {
				kept.push(passwordHash);
				return ledger.keep?.(s, i) ?? "conflict";
			},
		};
		const record = { subject: "s-alice", identifier: "alice", passwordHash: hash };
		expect(await (await opened(holding)).importer.record(record)).toBe("imported");
		expect(kept).toEqual([hash]);
		// A hash of another work than the ledger's: outside, writing nothing.
		const other = { ...record, passwordHash: testScryptHash("correct horse", 11) };
		expect(await (await opened(holding)).importer.record(other)).toBe("outside");
		expect(kept).toEqual([hash]);
		// A ledger holding no passwords takes no hash: outside, writing nothing.
		const held = new Map<string, string>();
		expect(await (await opened(keepingLedger(held))).importer.record(record)).toBe("outside");
		expect(held.size).toBe(0);
	});

	it("answers conflict for an identifier another subject holds, writing nothing of the record", async () => {
		const { importer, u } = await opened(keepingLedger(new Map([["alice", "s-alice"]])));
		const record = { subject: "s-mallory", identifier: "alice", verifiedEmail: "m@example.com" };
		expect(await importer.record(record)).toBe("conflict");
		expect(await u.contactsOf("s-mallory")).toEqual([]);
	});

	it("answers outside for an identifier where the ledger takes no import, writing nothing", async () => {
		const plain: Ledger = {
			verify: async () => none,
			bySubject: async () => none,
			byIdentifier: async () => none,
		};
		for (const { importer, u } of [
			await opened(plain),
			await opened(undefined, [testUser("bob", "p")]),
		]) {
			const record = { subject: "s-alice", identifier: "alice", verifiedEmail: "a@example.com" };
			expect(await importer.record(record)).toBe("outside");
			expect(await u.contactsOf("s-alice")).toEqual([]);
			expect(await importer.record({ subject: "s-alice", verifiedEmail: "a@example.com" })).toBe(
				"imported",
			);
		}
	});

	it("answers malformed for a record of another shape, a passkey's fields among them, asking no one", async () => {
		const calls: string[] = [];
		const ledger = keepingLedger();
		const { importer } = await opened({
			...ledger,
			keep: async (s, i) => {
				calls.push(i);
				return ledger.keep?.(s, i) ?? "conflict";
			},
		});
		for (const record of [
			null,
			[],
			"s-alice",
			{},
			{ subject: "" },
			{ subject: "s-é" },
			{ subject: "s-alice", identifier: "" },
			{ subject: "s-alice", identifier: 7 },
			{ subject: "s-alice", identifier: "a".repeat(256) },
			{ subject: "s-alice", verifiedEmail: "not an address" },
			{ subject: "s-alice", passkey: { id: "x" } },
			// A password's hash goes with an identifier, and is a hash read as one.
			{ subject: "s-alice", passwordHash: testScryptHash("p") },
			{ subject: "s-alice", identifier: "alice", passwordHash: "correct horse" },
			{ subject: "s-alice", identifier: "alice", passwordHash: 7 },
		]) {
			expect(await importer.record(record), JSON.stringify(record)).toBe("malformed");
		}
		expect(calls).toEqual([]);
	});

	it("answers full past a subject's 20 contacts, and unavailable where the ledger fails", async () => {
		const { importer } = await opened(keepingLedger());
		for (let i = 0; i < 20; i++) {
			expect(await importer.record({ subject: "s-a", verifiedEmail: `a${i}@example.com` })).toBe(
				"imported",
			);
		}
		expect(await importer.record({ subject: "s-a", verifiedEmail: "late@example.com" })).toBe(
			"full",
		);
		const failing = await opened({
			...keepingLedger(),
			keep: async () => {
				throw new Error("down");
			},
		});
		await expect(failing.importer.record({ subject: "s-a", identifier: "a" })).rejects.toSatisfy(
			isUnavailable,
		);
		const odd = await opened({ ...keepingLedger(), keep: async () => "maybe" as never });
		await expect(odd.importer.record({ subject: "s-a", identifier: "a" })).rejects.toSatisfy(
			isUnavailable,
		);
	});

	it("leaves the identifier kept where the email then meets a full subject, and answers alike when run again", async () => {
		const held = new Map<string, string>();
		const { importer, u } = await opened(keepingLedger(held));
		for (let i = 0; i < 20; i++)
			await importer.record({ subject: "s-a", verifiedEmail: `a${i}@example.com` });
		const record = { subject: "s-a", identifier: "a", verifiedEmail: "late@example.com" };
		expect(await importer.record(record)).toBe("full");
		expect(held.get("a")).toBe("s-a");
		expect(await importer.record(record)).toBe("full");
		expect([...held]).toEqual([["a", "s-a"]]);
		expect(await u.contactsOf("s-a")).toHaveLength(20);
	});

	it("leaves the identifier kept where the contact store fails after it, and imports the rest when run again", async () => {
		const held = new Map<string, string>();
		const down = unavailableSwitch<ContactStore>("contact store");
		const stores = switchedModule(memoryUsersStores().module, contactStore, down);
		const { importer, u } = await opened(keepingLedger(held), [], stores);
		const record = { subject: "s-a", identifier: "a", verifiedEmail: "a@example.com" };
		down.unavailable("save", "read", "update");
		await expect(importer.record(record)).rejects.toSatisfy(isUnavailable);
		expect(held.get("a")).toBe("s-a");
		down.restore();
		expect(await importer.record(record)).toBe("imported");
		expect(await u.contactsOf("s-a")).toEqual([{ kind: "email", value: "a@example.com" }]);
	});

	it("keeps an email for a subject with no identifier, asking the ledger nothing, whether or not it holds the subject", async () => {
		const asked: string[] = [];
		const ledger = keepingLedger();
		const { importer, u } = await opened({
			...ledger,
			bySubject: async (subject) => {
				asked.push(subject);
				return none;
			},
			keep: async (subject, identifier) => {
				asked.push(identifier);
				return ledger.keep?.(subject, identifier) ?? "conflict";
			},
		});
		expect(await importer.record({ subject: "s-nobody", verifiedEmail: "n@example.com" })).toBe(
			"imported",
		);
		expect(asked).toEqual([]);
		expect(await u.contactsOf("s-nobody")).toEqual([{ kind: "email", value: "n@example.com" }]);
	});
});
