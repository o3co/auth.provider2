import { describe, expect, it } from "vitest";
import { binding, lifetimeMs, now, recordsAt } from "../../../test/fixtures.ts";
import { familySubjectOf } from "../../erasure/erasure.ts";
import {
	type FamilyRecord,
	listedPerBucket,
	live,
	nameOf,
	read,
	rootedOf,
	write,
} from "../../record.ts";
import { removalOver, rootedOver } from "../rooted.ts";

// A subject's families by their root key (Q46): listed as founded, ended by a key's removal or all
// at a reset, in the bucket of their founding, the one before or the one after; a family whose root
// key the subject holds now is never ended; erased with their subject.

const familyOf = (subject: string, credential: string, end: number): FamilyRecord => ({
	format: 1,
	subject,
	client: "app",
	session: "sess-1",
	scope: ["read"],
	audience: ["https://api"],
	amr: ["pop", "user"],
	authTime: end - lifetimeMs,
	end,
	binding,
	statement: "t",
	assertion: "{}",
	credential,
	registration: "r-key",
	publicKey: "pk",
	generation: 4,
	secret: "s",
	code: "c",
});

/** Records in memory, and families founded and listed for subjects under their root keys; `held` the root keys held now. */
function world() {
	const at = recordsAt();
	const held = new Set<string>();
	const { list, rooted } = rootedOver({
		records: at.records,
		lifetimeMs,
		now: at.now,
		held: async (subject, credential) => held.has(`${subject} ${credential}`),
	});
	const found = async (family: string, subject: string, credential: string) => {
		const record = familyOf(subject, credential, at.now() + lifetimeMs);
		await at.records.create(nameOf.family(family), write.family(record), lifetimeMs, subject);
		await list({ subject, family, credential });
	};
	const isLive = async (family: string) =>
		live(read.family(await at.records.read(nameOf.family(family))), at.now());
	return { at, held, rooted, found, isLive };
}

/** How far the clock moves from `now` to just past its bucket's end. */
const toNextBucket = (Math.floor(now / lifetimeMs) + 1) * lifetimeMs - now + 1;

describe("a subject's families by their root key (Q46)", () => {
	it("ends those rooted in a credential removed, or all of a subject's, leaving others", async () => {
		const w = world();
		await w.found("f1", "alice", "cred-1");
		await w.found("f2", "alice", "cred-1");
		await w.found("f3", "alice", "cred-2");
		await w.found("f4", "bob", "cred-1");
		await w.rooted.end("alice", "cred-1");
		expect(await Promise.all(["f1", "f2", "f3", "f4"].map(w.isLive))).toEqual([
			false,
			false,
			true,
			true,
		]);
		await w.rooted.endAll("bob");
		expect(await w.isLive("f4")).toBe(false);
		expect(await w.isLive("f3")).toBe(true);
	});

	it("keeps a family whose root key the subject holds now: a reset told late spares the generation after it", async () => {
		const w = world();
		await w.found("old", "alice", "cred-1");
		// After the reset, a new key and its family, before the reset's removal is told.
		w.held.add("alice cred-new");
		await w.found("new", "alice", "cred-new");
		await w.rooted.endAll("alice");
		expect(await w.isLive("old")).toBe(false);
		expect(await w.isLive("new")).toBe(true);
	});

	it("finds a family live now in its founding's bucket or the one before", async () => {
		const w = world();
		await w.found("f1", "alice", "cred-1");
		// Just past the bucket's end: f1 still lives, listed in the bucket before.
		w.at.move(toNextBucket);
		await w.found("f2", "alice", "cred-1");
		expect(await w.isLive("f1")).toBe(true);
		await w.rooted.end("alice", "cred-1");
		expect(await w.isLive("f1")).toBe(false);
		expect(await w.isLive("f2")).toBe(false);
	});

	it("finds one a host whose clock runs ahead listed in the bucket after", async () => {
		const w = world();
		w.at.move(toNextBucket);
		await w.found("f1", "alice", "cred-1");
		// Ended from a host whose clock is behind, in the bucket before.
		w.at.move(-2);
		expect(await w.isLive("f1")).toBe(true);
		await w.rooted.end("alice", "cred-1");
		expect(await w.isLive("f1")).toBe(false);
	});

	it(`lists ${listedPerBucket} families a bucket; one past them is held by the log and its end alone`, async () => {
		const w = world();
		for (let n = 0; n <= listedPerBucket; n++) await w.found(`f${n}`, "alice", "cred-1");
		await w.rooted.endAll("alice");
		expect(await w.isLive("f0")).toBe(false);
		expect(await w.isLive(`f${listedPerBucket}`)).toBe(true);
	});

	it("reads passkeys' removal at its boundary: a credential ends its families, a subject emptied all", async () => {
		const asked: string[] = [];
		const removal = removalOver({
			end: async (subject, credential) => {
				asked.push(`end ${subject} ${credential}`);
			},
			endAll: async (subject) => {
				asked.push(`endAll ${subject}`);
			},
		});
		await removal.removed("alice", "cred-1", false);
		await removal.removed("alice", "cred-2", true);
		expect(asked).toEqual(["end alice cred-1", "endAll alice"]);
	});

	it("throws a store's failure, so the removal is told again and ends it then", async () => {
		const w = world();
		await w.found("f1", "alice", "cred-1");
		const { records } = w.at;
		let fail = true;
		const failing = rootedOver({
			records: {
				...records,
				change: async (...args: Parameters<typeof records.change>) => {
					if (fail) throw new Error("store down");
					return records.change(...args);
				},
			},
			lifetimeMs,
			now: w.at.now,
			held: async () => false,
		});
		await expect(failing.rooted.end("alice", "cred-1")).rejects.toThrow("store down");
		expect(await w.isLive("f1")).toBe(true);
		fail = false;
		await failing.rooted.end("alice", "cred-1");
		expect(await w.isLive("f1")).toBe(false);
	});

	it("keeps its rooted list under its subject, so the subject's erasure takes it", async () => {
		const w = world();
		await w.found("f1", "alice", "cred-1");
		const name = rootedOf("alice", Math.floor(now / lifetimeMs));
		expect(w.at.subjects().get(name)).toBe("alice");
		const kept = await w.at.records.read(name);
		expect(await familySubjectOf(name, kept)).toEqual({ kind: "subject", subject: "alice" });
	});
});
