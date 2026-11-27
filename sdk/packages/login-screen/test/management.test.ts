import { continuations } from "@mod/continuation-wire";
import { canonicalText, hpke, purposes, typs } from "@mod/sdk-core-wire";
import { describe, expect, it, vi } from "vitest";
import { base64url, digest, utf8 } from "../src/bytes.ts";
import { challengeOf } from "../src/challenge.ts";
import { firstKey } from "../src/first-key/first-key.ts";
import { openSealed, sealTo } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { management } from "../src/management/management.ts";
import { passkeyAssertion, signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";

async function world(purpose: "passkey-add" | "passkey-manage" = "passkey-manage") {
	const ring = await signingKey("ES256", "core-1");
	const keys = await screenKeys();
	const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
		"deriveBits",
	])) as CryptoKeyPair;
	const sealingKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const statement = await signCompact(
		ring,
		{
			v: 1,
			iss: issuer,
			sid: "st-1",
			iat: 1,
			exp: 2,
			e_enc: keys.eEnc,
			e_sig: keys.eSig,
			nonce: "n1",
			purpose,
		},
		{ typ: typs.statement },
	);
	const read = await management.read(statement, { ring: [ring.jwk], keys, issuer, purpose });
	if ("error" in read) throw new Error(read.error);
	// The approving key's assertion over the statement, as the screen's get() answers it (V30).
	const approving = await passkeyAssertion(base64url(await challengeOf(statement, "get")));
	const assertion = approving.bytes;
	const h = await digest(statement);
	/**
	 * The completion the Core seals to E_enc, under its purpose and this statement's hash unless told,
	 * padded to its bucket unless told what to seal of the compact JWS.
	 */
	const sealed = async (
		payload: unknown,
		aad = hpke.completionAad(purpose, h),
		typ?: string,
		plain: (jws: string) => string = (jws) => hpke.paddedCompletion(jws, 0) ?? "",
	) =>
		sealTo(
			Buffer.from(keys.eEnc, "base64url"),
			utf8(hpke.info.completion),
			utf8(aad),
			utf8(plain(await signCompact(ring, payload, { typ: typ ?? typs.completion }))),
		);
	const approved = {
		v: 1,
		iss: issuer,
		t_hash: h,
		assertion_hash: await digest(assertion),
		iat: 1,
		exp: 2,
	};
	const options = { ring: [ring.jwk], keys, issuer, assertion };
	return {
		ring,
		keys,
		pair,
		sealingKey,
		statement,
		manage: read.manage,
		h,
		sealed,
		approved,
		options,
		approving,
	};
}

describe("management.continuation (V24)", () => {
	it("seals a rename's body and its E_sig signature to the Core, padded and bound to stage, statement and sequence", async () => {
		const w = await world();
		const body = { credential_id: "AQID", label: "Laptop" };
		const made = await management.continuation(w.manage, "rename", 2, body, w);
		if ("error" in made) throw new Error(made.error);
		const h = await digest(w.statement);
		const opened = await openSealed(
			w.pair,
			made.sealed,
			utf8(hpke.info.continuation),
			utf8(continuations.aad("rename", h, 2)),
		);
		const text = new TextDecoder().decode(opened);
		expect(new TextEncoder().encode(text)).toHaveLength(continuations.plainBytes);
		const read = continuations.readPlain("rename", text);
		expect(read?.body).toEqual(body);
		const key = await crypto.subtle.importKey(
			"jwk",
			{ ...w.keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		const input = continuations.of("rename", h, 2, await digest(canonicalText(body)));
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				key,
				Buffer.from(read?.sig ?? "", "base64url"),
				utf8(input),
			),
		).toBe(true);
		// Bound: another sequence's or stage's additional data opens nothing.
		for (const aad of [continuations.aad("rename", h, 3), continuations.aad("delete", h, 2)])
			expect(
				await openSealed(w.pair, made.sealed, utf8(hpke.info.continuation), utf8(aad)),
			).toBeUndefined();
	});

	it("seals every body to one length, whatever its credential and label", async () => {
		const w = await world();
		const short = await management.continuation(w.manage, "delete", 1, { credential_id: "AA" }, w);
		const long = await management.continuation(
			w.manage,
			"rename",
			1,
			{ credential_id: "A".repeat(1364), label: "鍵".repeat(64) },
			w,
		);
		if ("error" in short || "error" in long) throw new Error("not sealed");
		expect(short.sealed.ct.length).toBe(long.sealed.ct.length);
		expect(short.sealed.ct.length).toBe(continuations.plainBytes + 16);
	});

	it("refuses a statement it did not read, keys other than the ones it names, a sequence out of 1 to 16, and a body of no shape", async () => {
		const w = await world();
		const body = { credential_id: "AQID" };
		expect(await management.continuation({ ...w.manage }, "delete", 1, body, w)).toEqual({
			error: "statement",
		});
		expect(
			await management.continuation(w.manage, "delete", 1, body, {
				...w,
				keys: await screenKeys(),
			}),
		).toEqual({ error: "keys" });
		for (const seq of [0, 17, 1.5])
			expect(await management.continuation(w.manage, "delete", seq, body, w), String(seq)).toEqual({
				error: "sequence",
			});
		for (const bad of [{}, { credential_id: "a+b" }, { credential_id: "A".repeat(1365) }])
			expect(
				await management.continuation(w.manage, "delete", 1, bad, w),
				JSON.stringify(bad),
			).toEqual({
				error: "body",
			});
		expect(
			await management.continuation(w.manage, "rename", 1, { credential_id: "AA", label: "" }, w),
		).toEqual({ error: "body" });
	});

	it("refuses a passkey-add statement: it continues by a creation", async () => {
		const w = await world("passkey-add");
		expect(
			await management.continuation(w.manage, "delete", 1, { credential_id: "AQID" }, w),
		).toEqual({ error: "statement" });
	});

	it("reads only a statement of the purpose asked for", async () => {
		const w = await world();
		const other = await signCompact(
			w.ring,
			{
				v: 1,
				iss: issuer,
				sid: "s",
				iat: 1,
				exp: 2,
				e_enc: w.keys.eEnc,
				e_sig: w.keys.eSig,
				nonce: "n",
				purpose: purposes.passkeyAdd,
			},
			{ typ: typs.statement },
		);
		const options = { ring: [w.ring.jwk], keys: w.keys, issuer };
		expect(await management.read(other, { ...options, purpose: "passkey-manage" })).toEqual({
			error: "payload",
		});
		expect(await management.read(w.statement, { ...options, purpose: "passkey-add" })).toEqual({
			error: "payload",
		});
	});
});

describe("management.finish", () => {
	const rows = [{ credential_id: "AQID", label: "Laptop", created_at: 1 }];

	it("takes a passkey-manage's completion: the keys' list", async () => {
		const w = await world();
		const sealed = await w.sealed({ ...w.approved, purpose: purposes.passkeyManage, keys: rows });
		expect(await management.finish(w.manage, sealed, w.options)).toEqual({ keys: rows });
	});

	it("reads a completion only padded to a bucket: one unpadded, or padded off a bucket's length, does not open", async () => {
		const w = await world();
		const listing = { ...w.approved, purpose: purposes.passkeyManage, keys: rows };
		// Either bucket opens: the Core chooses it by the longest credential ID.
		const large = await w.sealed(
			listing,
			undefined,
			undefined,
			(jws) => hpke.paddedCompletion(jws, 1023) ?? "",
		);
		expect(await management.finish(w.manage, large, w.options)).toEqual({ keys: rows });
		for (const plain of [
			(jws: string) => jws,
			(jws: string) => `${hpke.paddedCompletion(jws, 0)} `,
			(jws: string) => jws.padEnd(16_383, " "),
		]) {
			const sealed = await w.sealed(listing, undefined, undefined, plain);
			expect(await management.finish(w.manage, sealed, w.options)).toEqual({ error: "open" });
		}
	});

	it("refuses a completion of another statement, assertion, issuer, additional data or typ, a rename's for a listing, and a statement it did not read", async () => {
		const w = await world();
		const listing = { ...w.approved, purpose: purposes.passkeyManage, keys: rows };
		const renamed = { stage: "rename", seq: 1, body_hash: w.h };
		for (const [sealed, error] of [
			[await w.sealed({ ...listing, t_hash: await digest("another") }), "statement"],
			[await w.sealed({ ...listing, assertion_hash: await digest("another") }), "assertion"],
			[await w.sealed({ ...listing, iss: "https://other.example" }), "issuer"],
			[await w.sealed({ ...listing, continued: renamed }), "continued"],
			[await w.sealed(listing, hpke.completionAad("passkey-add", w.h)), "open"],
			[await w.sealed(listing, undefined, typs.statement), "typ"],
			[await w.sealed({ ...listing, purpose: purposes.passkeyAdd }), "payload"],
		] as const)
			expect(await management.finish(w.manage, sealed, w.options), error).toEqual({ error });
		const sealed = await w.sealed(listing);
		expect(await management.finish({ ...w.manage }, sealed, w.options)).toEqual({
			error: "statement",
		});
	});

	/** A passkey-add's creation: of its path, its evidence the approved statement's hash, no ciphertext. */
	const creationFor = (w: Awaited<ReturnType<typeof world>>, over: Record<string, unknown> = {}) =>
		signCompact(
			w.ring,
			{
				v: 1,
				iss: issuer,
				sid: "st-1",
				iat: 1,
				exp: 2,
				e_enc: w.keys.eEnc,
				e_sig: w.keys.eSig,
				nonce: "cn",
				purpose: purposes.creation,
				creation: {
					account: "a***@example",
					basis: "passkey-add",
					evidence: w.h,
					subject: "sub-1",
					kg: 0,
					// The approving key (V30), the screen's own, where the creation is a passkey-add's.
					...(over.basis === undefined || over.basis === "passkey-add"
						? { approver_key: w.approving.jwk }
						: {}),
					options: {
						user_id: "dXNlcg",
						rp_id: "id.example",
						exclude_credentials: ["AQID"],
						algorithms: [-7],
					},
					...over,
				},
			},
			{ typ: typs.statement },
		);

	it("takes a passkey-add's completion: its creation, which the first key's next steps take", async () => {
		const w = await world("passkey-add");
		const creation = await creationFor(w);
		const sealed = await w.sealed({ ...w.approved, purpose: purposes.passkeyAdd, creation });
		const done = await management.finish(w.manage, sealed, w.options);
		if (!("creation" in done)) throw new Error(JSON.stringify(done));
		expect(done.creation.compact).toBe(creation);
		expect(await firstKey.createOptions(done.creation, { rpName: "Example" })).not.toHaveProperty(
			"error",
		);
	});

	it("refuses a passkey-add's creation of another path, evidence or screen", async () => {
		const w = await world("passkey-add");
		const other = await screenKeys();
		const theirs = await signCompact(
			w.ring,
			{
				v: 1,
				iss: issuer,
				sid: "st-1",
				iat: 1,
				exp: 2,
				e_enc: other.eEnc,
				e_sig: other.eSig,
				nonce: "cn",
				purpose: purposes.creation,
				creation: {
					account: "a",
					basis: "passkey-add",
					evidence: w.h,
					subject: "sub-1",
					kg: 0,
					// The right approving key, so another screen's keys are its one defect.
					approver_key: w.approving.jwk,
					options: {
						user_id: "dXNlcg",
						rp_id: "id.example",
						exclude_credentials: [],
						algorithms: [-7],
					},
				},
			},
			{ typ: typs.statement },
		);
		for (const [creation, error] of [
			[await creationFor(w, { basis: "first-key", ct_hash: w.h }), "basis"],
			[
				await creationFor(w, {
					basis: "sign-up",
					account: undefined,
					options: {
						user_id: "dXNlcg",
						rp_id: "id.example",
						exclude_credentials: ["AQID"],
						algorithms: [-7],
						user_name: "Example 7f3a",
					},
				}),
				"basis",
			],
			[await creationFor(w, { evidence: await digest("another") }), "evidence"],
			[theirs, "creation"],
		] as const) {
			const sealed = await w.sealed({ ...w.approved, purpose: purposes.passkeyAdd, creation });
			expect(await management.finish(w.manage, sealed, w.options), error).toEqual({ error });
		}
	});

	const finished = async (w: Awaited<ReturnType<typeof world>>, creation: string) =>
		management.finish(
			w.manage,
			await w.sealed({ ...w.approved, purpose: purposes.passkeyAdd, creation }),
			w.options,
		);

	it("refuses a creation naming another key than the one its own assertion verifies under, before create()", async () => {
		const w = await world("passkey-add");
		const other = await passkeyAssertion(base64url(await challengeOf(w.statement, "get")));
		expect(await finished(w, await creationFor(w, { approver_key: other.jwk }))).toEqual({
			error: "approver",
		});
		const ed = await passkeyAssertion("x", "EdDSA");
		expect(await finished(w, await creationFor(w, { approver_key: ed.jwk }))).toEqual({
			error: "approver",
		});
	});

	it("refuses a creation naming no key: sdk-core-wire takes none such, so it does not read", async () => {
		const w = await world("passkey-add");
		expect(await finished(w, await creationFor(w, { approver_key: undefined }))).toEqual({
			error: "creation",
		});
	});

	it("tells a key this browser cannot verify from another key", async () => {
		const w = await world("passkey-add");
		// Only the approving key's import is refused, as a browser without its key type refuses it.
		const importKey = crypto.subtle.importKey.bind(crypto.subtle);
		const spy = vi
			.spyOn(crypto.subtle, "importKey")
			.mockImplementation(((
				format: never,
				data: { x?: unknown },
				...rest: [never, never, never]
			) =>
				data?.x === w.approving.jwk.x
					? Promise.reject(new DOMException("no such key type", "NotSupportedError"))
					: importKey(format, data as never, ...rest)) as never);
		expect(await finished(w, await creationFor(w))).toEqual({ error: "unsupported" });
		spy.mockRestore();
	});
});

describe("management.renamed", () => {
	const rows = [{ credential_id: "AQID", label: "Desk", created_at: 1 }];

	it("takes the rename's answer naming the rename sent: the new keys' list", async () => {
		const w = await world();
		const made = await management.continuation(
			w.manage,
			"rename",
			2,
			{ credential_id: "AQID", label: "Desk" },
			w,
		);
		if ("error" in made) throw new Error(made.error);
		expect(made.sent.bodyHash).toBe(
			await digest(canonicalText({ credential_id: "AQID", label: "Desk" })),
		);
		const continued = { stage: "rename", seq: 2, body_hash: made.sent.bodyHash };
		const answer = await w.sealed({
			...w.approved,
			purpose: purposes.passkeyManage,
			keys: rows,
			continued,
		});
		expect(await management.renamed(made.sent, answer, w.options)).toEqual({
			keys: rows,
			applied: true,
		});
		// The Core answers with the list whether or not the rename took: it took only where the key
		// named holds the label sent; another's key, or a later rename taken first, does not.
		const asListed = async (keys: unknown[]) =>
			management.renamed(
				made.sent,
				await w.sealed({ ...w.approved, purpose: purposes.passkeyManage, keys, continued }),
				w.options,
			);
		const desk = { credential_id: "AQID", label: "Desk", created_at: 1 };
		expect(await asListed([desk])).toEqual({ keys: [desk], applied: true });
		expect(await asListed([{ ...desk, label: "Desk 2" }])).toMatchObject({ applied: false });
		expect(await asListed([{ ...desk, credential_id: "BAUG" }])).toMatchObject({ applied: false });
		// The key named is in no row (deleted, or never the person's): not applied.
		expect(await asListed([])).toEqual({ keys: [], applied: false });
	});

	it("refuses an answer naming an older sequence, another body or no rename, and a continuation it did not send or a delete's", async () => {
		const w = await world();
		const made = await management.continuation(
			w.manage,
			"rename",
			2,
			{ credential_id: "AQID", label: "Desk" },
			w,
		);
		if ("error" in made) throw new Error(made.error);
		const listing = { ...w.approved, purpose: purposes.passkeyManage, keys: rows };
		const named = { stage: "rename", seq: 2, body_hash: made.sent.bodyHash };
		for (const [answer, why] of [
			[{ ...listing, continued: { ...named, seq: 1 } }, "an older sequence"],
			[{ ...listing, continued: { ...named, body_hash: await digest("other") } }, "another body"],
			[listing, "no rename"],
			[
				{ ...listing, continued: { ...named, stage: "delete", refused: "last" } },
				"a delete's, the same sequence and body",
			],
		] as const)
			expect(await management.renamed(made.sent, await w.sealed(answer), w.options), why).toEqual({
				error: "continued",
			});
		const answer = await w.sealed({ ...listing, continued: named });
		expect(await management.renamed({ ...made.sent }, answer, w.options)).toEqual({
			error: "sent",
		});
		const deleted = await management.continuation(
			w.manage,
			"delete",
			3,
			{ credential_id: "AQID" },
			w,
		);
		if ("error" in deleted) throw new Error(deleted.error);
		expect(await management.renamed(deleted.sent, answer, w.options)).toEqual({ error: "sent" });
	});
});
