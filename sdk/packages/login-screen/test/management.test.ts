import { canonicalText, continuation, hpke, purposes, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { firstKey } from "../src/first-key.ts";
import { openSealed, sealTo } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { management } from "../src/management.ts";
import { signCompact, signingKey } from "./fixtures.ts";

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
	const assertion = utf8("the assertion's bytes");
	const h = await digest(statement);
	/** The completion the Core seals to E_enc, under its purpose and this statement's hash unless told. */
	const sealed = async (payload: unknown, aad = hpke.completionAad(purpose, h), typ?: string) =>
		sealTo(
			Buffer.from(keys.eEnc, "base64url"),
			utf8(hpke.info.completion),
			utf8(aad),
			utf8(await signCompact(ring, payload, { typ: typ ?? typs.completion })),
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
			utf8(continuation.aad("rename", h, 2)),
		);
		const text = new TextDecoder().decode(opened);
		expect(new TextEncoder().encode(text)).toHaveLength(continuation.plainBytes);
		const read = continuation.readPlain("rename", text);
		expect(read?.body).toEqual(body);
		const key = await crypto.subtle.importKey(
			"jwk",
			{ ...w.keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		const input = continuation.of("rename", h, 2, await digest(canonicalText(body)));
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				key,
				Buffer.from(read?.sig ?? "", "base64url"),
				utf8(input),
			),
		).toBe(true);
		// Bound: another sequence's or stage's additional data opens nothing.
		for (const aad of [continuation.aad("rename", h, 3), continuation.aad("delete", h, 2)])
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
		expect(short.sealed.ct.length).toBe(continuation.plainBytes + 16);
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
			[await creationFor(w, { basis: "sign-up" }), "basis"],
			[await creationFor(w, { evidence: await digest("another") }), "evidence"],
			[theirs, "creation"],
		] as const) {
			const sealed = await w.sealed({ ...w.approved, purpose: purposes.passkeyAdd, creation });
			expect(await management.finish(w.manage, sealed, w.options), error).toEqual({ error });
		}
	});
});
