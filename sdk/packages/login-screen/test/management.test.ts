import { canonicalText, continuation, hpke, purposes, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { openSealed } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { management } from "../src/management.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";

async function world() {
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
			purpose: purposes.passkeyManage,
		},
		{ typ: typs.statement },
	);
	const read = await management.read(statement, { ring: [ring.jwk], keys, issuer });
	if ("error" in read) throw new Error(read.error);
	return { ring, keys, pair, sealingKey, statement, manage: read.manage };
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

	it("reads only a passkey-manage statement", async () => {
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
		expect(await management.read(other, { ring: [w.ring.jwk], keys: w.keys, issuer })).toEqual({
			error: "payload",
		});
	});
});
