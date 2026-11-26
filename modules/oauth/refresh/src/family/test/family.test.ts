import type { BundlePart } from "@mod/grants";
import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	binding,
	jkt,
	lifetimeMs,
	now,
	recordsAt,
	request,
	statement,
} from "../../../test/fixtures.ts";
import { nameOf, read, sha256, tokenOf } from "../../record.ts";
import { rootedOver } from "../../rooted/rooted.ts";
import { type FoundingParts, founding } from "../family.ts";

const secret = "s".repeat(43);
const iat = now / 1000 - 10;

/** The founding over records in memory, an approval and a key as found, recording what it followed. */
function world(over: Partial<FoundingParts> = {}) {
	const records = recordsAt();
	const followed: unknown[][] = [];
	const audited: unknown[] = [];
	const maker = founding({
		records: records.records,
		approvals: {
			rootOf: async (hash) =>
				hash === "t-hash" ? { statement, assertion: "{}", credential: "cred-1" } : undefined,
		},
		passkeys: {
			publicKeyOf: async (credential) =>
				credential === "cred-1"
					? { subject: "alice", publicKey: "pk", registration: "r-key" }
					: undefined,
		},
		// This Core is of generation 5; the statement was signed by generation 4's ring.
		keys: {
			generation: () => 5,
			verifyOf: async (g, jws) =>
				g === 4 && jws === statement
					? { kind: "valid", claims: {} }
					: { kind: "invalid", reason: "signature" },
		},
		selections: {
			follow: async (...args) => {
				followed.push(args);
			},
		},
		lifetimeMs,
		now: records.now,
		secret: () => secret,
		list: rootedOver({
			records: records.records,
			lifetimeMs,
			now: records.now,
			held: async () => false,
		}).list,
		audit: {
			record: (event) => {
				audited.push(event);
			},
			lost: () => ({}),
		},
		...over,
	});
	return { records, maker, followed, audited };
}

/** A part founded, prepared, signed and committed as the bundle's record `placed` would. */
async function founded(w: ReturnType<typeof world>, id = "r-bundle", asked = request) {
	const part = (await w.maker.part(asked)) as BundlePart;
	const ready = await part.prepare(now);
	const placed = { id, acceptedAt: now };
	const token = await part.sign(ready.prepared, "h.p.s", placed);
	await part.commit?.(ready.prepared, placed);
	return { part, ready, token };
}

describe("a family, founded with a code's redemption", () => {
	it("rests on its approval's root and key, kept by its bundle record's id once committed, its token that id and a secret", async () => {
		const w = world();
		const { token, ready } = await founded(w);
		expect(token).toBe(tokenOf("r-bundle", secret));
		const family = read.family(await w.records.records.read(nameOf.family("r-bundle")));
		expect(family).toEqual({
			format: 1,
			subject: "alice",
			client: "app",
			session: "sess-1",
			scope: ["read"],
			audience: ["https://api"],
			amr: ["pop", "user"],
			authTime: request.approvedAt,
			// Its statement's issue and the delegation's length (O27).
			end: iat * 1000 + lifetimeMs,
			binding,
			statement,
			assertion: "{}",
			credential: "cred-1",
			registration: "r-key",
			publicKey: "pk",
			generation: 4,
			secret: sha256(secret),
			code: "code-digest",
		});
		expect(ready.digest).toMatch(/^[\w-]{43}$/);
		expect(read.key(await w.records.records.read(nameOf.key(jkt)))).toEqual({
			format: 1,
			subject: "alice",
			family: "r-bundle",
		});
		expect(read.code(await w.records.records.read(nameOf.code("code-digest")))).toEqual({
			format: 1,
			subject: "alice",
			family: "r-bundle",
		});
		expect(w.followed).toEqual([
			["code-digest", "r-bundle", iat * 1000 + lifetimeMs - now + 120_000],
		]);
		expect(w.records.subjects().get(nameOf.family("r-bundle"))).toBe("alice");
	});

	it("keeps nothing before it is committed: signing alone founds no family", async () => {
		const w = world();
		const part = (await w.maker.part(request)) as BundlePart;
		const ready = await part.prepare(now);
		await part.sign(ready.prepared, "h.p.s", { id: "r-bundle", acceptedAt: now });
		expect(await w.records.records.read(nameOf.family("r-bundle"))).toBeUndefined();
	});

	it("is refused where its approval or key is gone, its key another subject's, no key bound, or the key bound to another live family", async () => {
		const gone = { ...request, statement: "no-such-hash" };
		expect(await world().maker.part(gone)).toEqual({ refused: "the approval it rests on is gone" });
		const keyless = world({ passkeys: { publicKeyOf: async () => undefined } });
		expect(await keyless.maker.part(request)).toEqual({ refused: "the key it rests on is gone" });
		const others = world({
			passkeys: {
				publicKeyOf: async () => ({ subject: "bob", publicKey: "pk", registration: "r" }),
			},
		});
		expect(await others.maker.part(request)).toEqual({ refused: "the key it rests on is gone" });
		const { binding: _, ...unbound } = request;
		expect(await world().maker.part(unbound)).toEqual({ refused: "no key the family is bound to" });
		const w = world();
		await founded(w);
		expect(await w.maker.part({ ...request, code: "code-2" })).toEqual({
			refused: "the key is bound to another family",
			told: "the DPoP key is bound to another refresh family",
		});
		// Recorded for the operator: whose, which client, which key; never a token.
		expect(w.audited).toEqual([
			{
				kind: "refresh.key_bound",
				subject: "alice",
				attributes: {
					client: request.clientId,
					binding: request.binding?.member,
					thumbprint: request.binding?.confirmation,
				},
			},
		]);
		// Revoked, it holds its key until its end all the same; past it, the key is free.
		await w.maker.revoke("code-digest", "alice");
		expect(await w.maker.part({ ...request, code: "code-2" })).toMatchObject({
			refused: expect.any(String),
		});
		w.records.move(lifetimeMs + 120_000);
		expect(await w.maker.part({ ...request, code: "code-3" })).not.toHaveProperty("refused");
	});

	it("claims its key by the index's one create: of two founded at once with one key, only the first lives", async () => {
		const w = world();
		const parts = await Promise.all([
			w.maker.part(request),
			w.maker.part({ ...request, code: "code-2" }),
		]);
		const [first, second] = parts as BundlePart[];
		const ready = await Promise.all([first?.prepare(now), second?.prepare(now)]);
		await first?.commit?.(ready[0]?.prepared, { id: "r-1", acceptedAt: now });
		await expect(
			second?.commit?.(ready[1]?.prepared, { id: "r-2", acceptedAt: now }),
		).rejects.toSatisfy(isUnavailable);
		const at = async (id: string) => read.family(await w.records.records.read(nameOf.family(id)));
		expect((await at("r-1"))?.revoked).toBeUndefined();
		expect((await at("r-2"))?.revoked).toBe(true);
		expect(read.key(await w.records.records.read(nameOf.key(jkt)))?.family).toBe("r-1");
		// The one that lost the key is recorded as one refused at its part is.
		expect(w.audited).toEqual([
			expect.objectContaining({
				kind: "refresh.key_bound",
				subject: "alice",
				attributes: expect.objectContaining({ thumbprint: jkt }),
			}),
		]);
	});

	it("ends itself where its commit fails midway, and records the generation that signed its statement", async () => {
		const failing = world({
			selections: {
				follow: async () => {
					throw new Error("claims-selection down");
				},
			},
		});
		await expect(founded(failing)).rejects.toThrow("claims-selection down");
		expect(
			read.family(await failing.records.records.read(nameOf.family("r-bundle")))?.revoked,
		).toBe(true);
		const w = world();
		await founded(w);
		expect(read.family(await w.records.records.read(nameOf.family("r-bundle")))?.generation).toBe(
			4,
		);
		const unsigned = world({
			keys: {
				generation: () => 7,
				verifyOf: async () => ({ kind: "invalid", reason: "signature" }),
			},
		});
		expect(await unsigned.maker.part(request)).toEqual({
			refused: "the statement it rests on does not verify",
		});
	});

	it("ends itself where listing it under its root key fails, its DPoP key claimed to its end (Q27)", async () => {
		const failing = world({
			list: async () => {
				throw new Error("store down");
			},
		});
		await expect(founded(failing)).rejects.toThrow("store down");
		const { records } = failing.records;
		expect(read.family(await records.read(nameOf.family("r-bundle")))?.revoked).toBe(true);
		expect(read.key(await records.read(nameOf.key(jkt)))?.family).toBe("r-bundle");
	});

	it("ends itself where its root key was removed between its part and its commit (Q46)", async () => {
		let reads = 0;
		const removed = world({
			passkeys: {
				// Found as the part reads it; gone when the commit reads it again.
				publicKeyOf: async () =>
					reads++ === 0 ? { subject: "alice", publicKey: "pk", registration: "r-key" } : undefined,
			},
		});
		await expect(founded(removed)).rejects.toSatisfy(isUnavailable);
		expect(
			read.family(await removed.records.records.read(nameOf.family("r-bundle")))?.revoked,
		).toBe(true);
	});

	it("lets one of two commits interleaved on one key live, and ends a family whose code is voided mid-commit", async () => {
		const w = world();
		const { records } = w.records;
		// Both commits reach the key's create before either reads it back.
		let waiting: (() => void)[] = [];
		const barrier = () =>
			new Promise<void>((resolve) => {
				waiting.push(resolve);
				if (waiting.length === 2) for (const go of waiting) go();
			});
		const create = records.create;
		records.create = async (name, ...rest) => {
			if (name === nameOf.key(jkt)) await barrier();
			return create(name, ...rest);
		};
		const parts = (await Promise.all([
			w.maker.part(request),
			w.maker.part({ ...request, code: "code-2" }),
		])) as BundlePart[];
		const ready = await Promise.all(parts.map((p) => p.prepare(now)));
		const outcomes = await Promise.allSettled(
			parts.map((p, i) => p.commit?.(ready[i]?.prepared, { id: `r-${i}`, acceptedAt: now })),
		);
		expect(outcomes.map((o) => o.status).sort()).toEqual(["fulfilled", "rejected"]);
		const lived = await Promise.all(
			["r-0", "r-1"].map(
				async (id) => !read.family(await records.read(nameOf.family(id)))?.revoked,
			),
		);
		expect(lived.filter(Boolean)).toHaveLength(1);
		records.create = create;
		waiting = [];
		// A code voided as its family links to it: the family is ended either way.
		const v = world();
		const read0 = v.records.records.read;
		let once = true;
		v.records.records.read = async (name) => {
			if (once && name === nameOf.code("code-digest")) {
				once = false;
				await v.maker.revoke("code-digest", "alice");
			}
			return read0(name);
		};
		await expect(founded(v)).rejects.toSatisfy(isUnavailable);
		expect(read.family(await read0(nameOf.family("r-bundle")))?.revoked).toBe(true);
	});

	it("ends itself where linking its code or claiming its key fails, its key held to its end where it was claimed", async () => {
		for (const failing of [nameOf.code("code-digest"), nameOf.key(jkt)]) {
			const w = world();
			const { records } = w.records;
			const [create, change] = [records.create, records.change];
			records.create = async (name, ...rest) => {
				if (name === failing) throw new Error("the store fell");
				return create(name, ...rest);
			};
			records.change = async (name, ...rest) => {
				if (name === failing) throw new Error("the store fell");
				return change(name, ...rest);
			};
			await expect(founded(w), failing).rejects.toThrow("the store fell");
			expect(read.family(await records.read(nameOf.family("r-bundle")))?.revoked, failing).toBe(
				true,
			);
		}
		// Claimed, then failing after: the key stays held to the family's end, then is free.
		const w = world({
			selections: {
				follow: async () => {
					throw new Error("claims-selection down");
				},
			},
		});
		await expect(founded(w)).rejects.toThrow("claims-selection down");
		expect(await w.maker.part({ ...request, code: "code-2" })).toEqual({
			refused: "the key is bound to another family",
			told: "the DPoP key is bound to another refresh family",
		});
		w.records.move(lifetimeMs + 120_000);
		expect(await w.maker.part({ ...request, code: "code-3" })).not.toHaveProperty("refused");
	});

	it("is ended with its code: a code voided after it was kept, or before, which it is ended at as it is kept", async () => {
		const w = world();
		await founded(w);
		await w.maker.revoke("code-digest", "alice");
		expect(read.family(await w.records.records.read(nameOf.family("r-bundle")))?.revoked).toBe(
			true,
		);
		const early = world();
		await early.maker.revoke("code-digest", "alice");
		await expect(founded(early)).rejects.toSatisfy(isUnavailable);
		expect(read.family(await early.records.records.read(nameOf.family("r-bundle")))?.revoked).toBe(
			true,
		);
		// Revoking again, or a code that founded none, does no harm; with no subject, the code's record
		// gone, nothing is marked.
		await w.maker.revoke("code-digest", "alice");
		await w.maker.revoke("code-none");
		expect(await w.records.records.read(nameOf.code("code-none"))).toBeUndefined();
	});
});
