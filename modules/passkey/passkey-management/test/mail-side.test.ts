import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { Keys } from "@mod/keys";
import { firstKey } from "@mod/sdk-core-wire";
import type { Verified } from "@mod/users";
import { describe, expect, it } from "vitest";
import type { StoredNonce, StoredToken } from "../src/contract.ts";
import type { Created, CreationAsk } from "../src/creation/creation.ts";
import { mailSideOver } from "../src/mail-side/mail-side.ts";
import { noncesOver } from "../src/nonces/nonces.ts";
import type { SealedRequest } from "../src/sealed/sealed.ts";
import { tokensOver } from "../src/tokens/tokens.ts";
import { memoryKept } from "./fixtures/kept.ts";
import { screenPoints } from "./fixtures/screen.ts";

const b64 = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const right = "12345678";
const refused = (reason: string) => ({ kind: "refused", reason });

/** A mail's side's world: its stores in memory, the opening and the creation as stand-ins. */
async function world(p: { created?: () => Created } = {}) {
	let now = 0;
	const nonces = noncesOver({
		store: memoryKept<StoredNonce>().store,
		random: (n) => randomBytes(n),
		lifetimeMs: 120_000,
	});
	const tokens = tokensOver({
		store: memoryKept<StoredToken>().store,
		random: (n) => randomBytes(n),
		now: () => now,
		lifetimeMs: 900_000,
		tries: 3,
	});
	let plain: unknown;
	let holder = "s-alice";
	const keys: Pick<Keys, "open"> = {
		open: async () => ({
			kind: "opened",
			plaintext: new TextEncoder().encode(JSON.stringify(plain)),
		}),
	};
	const asked: CreationAsk[] = [];
	const side = mailSideOver({
		keys,
		nonces,
		users: {
			byIdentifier: async (identifier): Promise<Verified> =>
				identifier === "alice"
					? { kind: "user", user: { subject: holder, attributes: {} } }
					: { kind: "none" },
		},
		tokens,
		create: async (ask) => {
			asked.push(ask);
			return (
				p.created?.() ?? {
					kind: "issued",
					statement: `statement-${asked.length}`,
					hash: "h",
					challenge: "c",
				}
			);
		},
	});
	const signer = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = signer.publicKey.export({ format: "jwk" });
	const request = async (text: { token: string; identifier: string; code: string }) => {
		plain = text;
		const sealed: SealedRequest = {
			nonce: await nonces.issue("mail"),
			...screenPoints(),
			eSigX: new Uint8Array(Buffer.from(jwk.x as string, "base64url")),
			eSigY: new Uint8Array(Buffer.from(jwk.y as string, "base64url")),
			enc: randomBytes(65),
			ct: randomBytes(40),
		};
		return sealed;
	};
	const digestOf = (r: SealedRequest) =>
		createHash("sha256").update(r.enc).update(r.ct).digest("base64url");
	const recovery = (r: SealedRequest, key = signer.privateKey) => {
		const digest = digestOf(r);
		const sig = sign("sha256", Buffer.from(firstKey.recoverInput(r.nonce, digest)), {
			key,
			dsaEncoding: "ieee-p1363",
		});
		return { nonce: r.nonce, digest, sig: b64(sig) };
	};
	return {
		side,
		tokens,
		request,
		recovery,
		digestOf,
		asked,
		later: (ms: number) => {
			now += ms;
		},
		lookupNames: (subject: string) => {
			holder = subject;
		},
	};
}

describe("a first key's mail's side", () => {
	it("answers the creation for the token's subject, its evidence, ciphertext hash and when it began", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 250);
		const r = await w.request({ token, identifier: "alice", code: right });
		expect(await w.side.mail(r)).toEqual({ kind: "answered", statement: "statement-1" });
		expect(w.asked).toEqual([
			expect.objectContaining({
				subject: "s-alice",
				account: "a***",
				basis: "first-key",
				evidence: createHash("sha256").update(firstKey.evidenceInput(token)).digest("base64url"),
				ctHash: w.digestOf(r),
				since: 250,
			}),
		]);
	});

	it("makes the creation for the token's own subject when the same request is taken up after a fault, the lookup since changed", async () => {
		let fails = true;
		const w = await world({
			created: () => {
				if (!fails) return { kind: "issued", statement: "after", hash: "h", challenge: "c" };
				fails = false;
				return { kind: "refused", reason: "busy" };
			},
		});
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const r = await w.request({ token, identifier: "alice", code: right });
		expect(await w.side.mail(r)).toEqual({ kind: "unavailable", reason: "busy" });
		w.lookupNames("s-bob");
		expect(await w.side.mail(r)).toEqual({ kind: "answered", statement: "after" });
		expect(w.asked.map((a) => a.subject)).toEqual(["s-alice", "s-alice"]);
	});

	it("answers two at once, and the same request again, with the one creation kept", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const r = await w.request({ token, identifier: "alice", code: right });
		const both = await Promise.all([w.side.mail(r), w.side.mail(r)]);
		const kept = both.find((a) => a.kind === "answered");
		expect(kept).toBeDefined();
		for (const answer of both) expect(answer).toEqual(kept);
		expect(await w.side.mail(r)).toEqual(kept);
	});

	it("refuses a wrong code counted once, the same nonce with other bytes, and any other request once one is answered", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const wrong = await w.request({ token, identifier: "alice", code: "00000000" });
		for (let i = 0; i < 3; i++) expect(await w.side.mail(wrong)).toEqual(refused("token"));
		const r = await w.request({ token, identifier: "alice", code: right });
		expect((await w.side.mail(r)).kind).toBe("answered");
		expect(await w.side.mail({ ...r, ct: randomBytes(40) })).toEqual(refused("nonce"));
		const other = await w.request({ token, identifier: "alice", code: right });
		expect(await w.side.mail(other)).toEqual(refused("token"));
		expect(w.asked).toHaveLength(1);
	});

	it("refuses an identifier naming another or no subject, and a subject revoked since", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const bob = await w.request({ token, identifier: "bob", code: right });
		expect(await w.side.mail(bob)).toEqual(refused("token"));
		const revoked = await world({ created: () => ({ kind: "refused", reason: "revoked" }) });
		const t2 = (await revoked.tokens.issue("s-alice", right, 0)).token;
		const r2 = await revoked.request({ token: t2, identifier: "alice", code: right });
		expect(await revoked.side.mail(r2)).toEqual(refused("revoked"));
	});

	it("gives nothing once the token ended, an answer kept or not", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const r = await w.request({ token, identifier: "alice", code: right });
		await w.side.mail(r);
		w.later(900_001);
		expect(await w.side.mail(r)).toEqual(refused("token"));
		// Claimed, no answer kept yet, then past the end: taken up, it gets none.
		let busy = true;
		const claimed = await world({
			created: () => {
				if (!busy) return { kind: "issued", statement: "late", hash: "h", challenge: "c" };
				busy = false;
				return { kind: "refused", reason: "busy" };
			},
		});
		const t2 = (await claimed.tokens.issue("s-alice", right, 0)).token;
		const r2 = await claimed.request({ token: t2, identifier: "alice", code: right });
		expect((await claimed.side.mail(r2)).kind).toBe("unavailable");
		claimed.later(900_001);
		expect(await claimed.side.mail(r2)).toEqual(refused("token"));
	});
});

describe("a first key's recovery", () => {
	it("answers the creation kept for a request its E_sig signed for, completing its token's use, and nothing else", async () => {
		const w = await world();
		const { token } = await w.tokens.issue("s-alice", right, 0);
		const r = await w.request({ token, identifier: "alice", code: right });
		const q = { nonce: r.nonce, digest: w.digestOf(r) };
		// A fall after the answer was kept, before the token was used: the recovery completes it.
		await w.tokens.attempt(token, q, "s-alice", right);
		await w.tokens.keep(q, token, {
			eSig: { kty: "EC", crv: "P-256", x: b64(r.eSigX), y: b64(r.eSigY) },
			statement: "kept",
		});
		const asked = w.recovery(r);
		expect(await w.side.recover(asked)).toEqual({ kind: "answered", statement: "kept" });
		const other = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
		expect(await w.side.recover(w.recovery(r, other))).toEqual(refused("recovery"));
		expect(await w.side.recover({ ...asked, digest: "other" })).toEqual(refused("recovery"));
		w.later(900_001);
		expect(await w.side.recover(asked)).toEqual(refused("recovery"));
	});
});
