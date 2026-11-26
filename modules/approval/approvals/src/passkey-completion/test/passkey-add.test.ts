import { hpke, payloads, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { creationItems, issued, payloadOf } from "../../../test/fixtures/statements.ts";
import { openSealed, screenKeys, sha256, world } from "../../../test/fixtures/world.ts";
import { passkeyAddCompletionsOver } from "../passkey-add.ts";

describe("a passkey-add's completion", () => {
	/** A passkey-add used by an assertion, and a creation issued for it to the same screen. */
	async function approved(w: Awaited<ReturnType<typeof world>>) {
		await w.plant("s1");
		const keys = screenKeys();
		const a = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: keys.screen,
			by: "src",
		});
		if (a.kind !== "issued") throw new Error(a.reason);
		const assertion = w.assert(a.challenge);
		await w.approvals.use({ statement: a.statement, assertion });
		const { ct_hash: _none, ...rest } = creationItems;
		const creationFor = async (items: object, screen = keys.screen) => {
			const c = await w.approvals.issue({
				purpose: "creation",
				// A member given as undefined is none: a sign-up's names no account.
				items: JSON.parse(
					JSON.stringify({ ...rest, basis: "passkey-add", evidence: a.hash, ...items }),
				) as never,
				screen,
				by: "s1",
			});
			if (c.kind !== "issued") throw new Error(c.reason);
			return c.statement;
		};
		return { keys, a, assertion, creation: await creationFor({}), creationFor };
	}

	it("signs the creation made for it, sealed to its screen under its purpose and hash, and keeps it", async () => {
		const w = await world();
		const { keys, a, assertion, creation, creationFor } = await approved(w);
		const done = await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation });
		if (done.kind !== "completed") throw new Error(done.reason);
		const opened = openSealed(
			keys.encKey,
			done,
			hpke.info.completion,
			hpke.completionAad("passkey-add", a.hash),
		);
		// Padded to the smaller bucket: none of its excluded keys is longer than 128 bytes.
		expect(opened).toHaveLength(hpke.completionBuckets[0]);
		const jws = hpke.unpaddedCompletion(opened) as string;
		expect(await w.keys.verify("core", jws, typs.completion)).toMatchObject({ kind: "valid" });
		const payload = payloadOf(jws);
		expect(payloads.completions.passkeyAdd.safeParse(payload).success).toBe(true);
		expect(payload).toMatchObject({
			purpose: "passkey-add",
			t_hash: a.hash,
			assertion_hash: sha256(assertion),
			creation,
		});
		// The one kept is answered, asked with no creation or another, and past the statement's expiry.
		const other = await creationFor({});
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual(done);
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation: other }),
		).toEqual(done);
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual(done);
		// Past its expiry the passkey-add is given no more; its record reads as used, its completion kept.
		expect(await w.approvals.passkeyAddOf(a.hash)).toBeUndefined();
		expect(await w.approvals.usedOf(a.hash)).toMatchObject({
			purpose: "passkey-add",
			completed: true,
		});
	});

	it("keeps nothing where signing or sealing fails, and completes it when asked again", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const over = (keys: typeof w.keys) =>
			passkeyAddCompletionsOver({
				keys,
				store: w.statements.store,
				issuer: "https://issuer.example",
				now: () => 1_800_000_000_000,
			});
		const withdrawn = over({ ...w.keys, sign: async () => ({ kind: "withdrawn" }) as never });
		expect(await withdrawn({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "withdrawn",
		});
		const unsealed = over({
			...w.keys,
			seal: async () => {
				throw new Error("sealing fell");
			},
		});
		await expect(unsealed({ hash: a.hash, assertion, creation })).rejects.toThrow("sealing fell");
		// Still used, none kept: asked with no creation it answers none, and with one it completes.
		expect(await w.approvals.usedOf(a.hash)).not.toHaveProperty("completed");
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation }),
		).toMatchObject({
			kind: "completed",
		});
	});

	it("answers the one kept only to the assertion that used it", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const done = await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation });
		expect(done.kind).toBe("completed");
		const another = w.assert(a.challenge);
		for (const ask of [{ assertion: another }, { assertion: another, creation }])
			expect(await w.approvals.completePasskeyAdd({ hash: a.hash, ...ask })).toEqual({
				kind: "refused",
				reason: "assertion",
			});
	});

	it("makes none for a passkey-add whose bytes this generation's ring does not verify", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const [head, body] = a.statement.split(".");
		const other = `${head}.${body}.${Buffer.alloc(64).toString("base64url")}`;
		await w.statements.store.change(a.hash, (r) => ({
			value: { ...(r as object), jws: other } as never,
		}));
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
	});

	it("is no authorization: completed or rooted as one, it answers none", async () => {
		const w = await world();
		const { a } = await approved(w);
		expect(await w.approvals.complete({ hash: a.hash, code: "c" })).toEqual({
			kind: "refused",
			reason: "purpose",
		});
		expect(await w.approvals.rootOf(a.hash)).toBeUndefined();
	});

	it("keeps one of two creations asked at once, and answers it to both", async () => {
		const w = await world();
		const { a, assertion, creation, creationFor } = await approved(w);
		const other = await creationFor({});
		const [one, two] = await Promise.all([
			w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation }),
			w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation: other }),
		]);
		expect(one.kind).toBe("completed");
		expect(two).toEqual(one);
	});

	it("signs no creation but one issued here for it, to its screen, and answers none kept yet", async () => {
		const w = await world();
		const { a, assertion, creationFor } = await approved(w);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion })).toEqual({
			kind: "refused",
			reason: "unknown",
		});
		const refuses = async (creation: string) =>
			expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
				kind: "refused",
				reason: "creation",
			});
		// For another statement's evidence, another basis, or another screen's keys; or bytes not issued here.
		await refuses(await creationFor({ evidence: sha256("other") }));
		// A sign-up's creation names no account, its name in `user_name` alone.
		await refuses(
			await creationFor({
				basis: "sign-up",
				account: undefined,
				options: { ...creationItems.options, user_name: "Example 3fa9c1" },
			}),
		);
		await refuses(await creationFor({ subject: "s2" }));
		await refuses(await creationFor({}, screenKeys().screen));
		const [head, body] = (await creationFor({})).split(".");
		await refuses(`${head}.${body}.${Buffer.alloc(64).toString("base64url")}`);
	});

	it("answers no statement but a passkey-add used by that assertion, unexpired", async () => {
		const w = await world();
		const { a, assertion, creation } = await approved(w);
		const another = w.assert(a.challenge);
		expect(
			await w.approvals.completePasskeyAdd({ hash: a.hash, assertion: another, creation }),
		).toEqual({
			kind: "refused",
			reason: "assertion",
		});
		const t = await issued(w);
		const tAssertion = w.assert(t.challenge);
		await w.approvals.use({ statement: t.statement, assertion: tAssertion });
		expect(
			await w.approvals.completePasskeyAdd({ hash: t.hash, assertion: tAssertion, creation }),
		).toEqual({ kind: "refused", reason: "purpose" });
		const unused = await w.approvals.issue({
			purpose: "passkey-add",
			items: {},
			screen: screenKeys().screen,
			by: "src",
		});
		if (unused.kind !== "issued") throw new Error(unused.reason);
		expect(
			await w.approvals.completePasskeyAdd({ hash: unused.hash, assertion, creation }),
		).toEqual({ kind: "refused", reason: "unused" });
		w.advance(5 * 60_000 + 1000);
		expect(await w.approvals.completePasskeyAdd({ hash: a.hash, assertion, creation })).toEqual({
			kind: "refused",
			reason: "expired",
		});
	});
});
