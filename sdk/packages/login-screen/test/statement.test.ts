import { payloads, purposes, typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest } from "../src/bytes.ts";
import { challengeOf } from "../src/challenge.ts";
import { screenKeys } from "../src/keys.ts";
import { readStatement } from "../src/statement.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";
const approval = {
	client_id: "c1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "s",
	scope: "openid",
	nonce: "n",
	code_challenge: "cc",
	code_challenge_method: "S256",
	dpop_jkt: "jkt",
	jar_hash: "jh",
};

async function world() {
	const ring = await signingKey("ES256", "core-1");
	const keys = await screenKeys();
	const common = {
		v: 1,
		iss: issuer,
		sid: "st-1",
		iat: 1,
		exp: 2,
		e_enc: keys.eEnc,
		e_sig: keys.eSig,
	};
	const t = { ...common, purpose: purposes.authorization, approval };
	return { ring, keys, common, t };
}

describe("screenKeys", () => {
	it("makes an HPKE point and a P-256 signing key, the private halves held back", async () => {
		const keys = await screenKeys();
		expect(Buffer.from(keys.eEnc, "base64url")).toHaveLength(65);
		expect(Buffer.from(keys.eEnc, "base64url")[0]).toBe(4);
		expect(Object.keys(keys.eSig).sort()).toEqual(["crv", "kty", "x", "y"]);
		expect(keys.encryption.privateKey.extractable).toBe(false);
		expect(keys.signing.privateKey.extractable).toBe(false);
		const other = await screenKeys();
		expect(other.eEnc).not.toBe(keys.eEnc);
	});
});

describe("readStatement", () => {
	it("reads T signed by the ring, of its typ, naming this screen's keys and the issuer", async () => {
		const { ring, keys, t } = await world();
		const compact = await signCompact(ring, t, { typ: typs.statement });
		expect(
			await readStatement(compact, { purpose: "authorization", ring: [ring.jwk], keys, issuer }),
		).toEqual({ statement: payloads.statement.parse(t), compact });
	});

	it("reads a creation and a possession by their purposes' schemas", async () => {
		const { ring, keys, common } = await world();
		const creation = {
			...common,
			nonce: "n1",
			purpose: purposes.creation,
			creation: {
				account: "a***@example",
				evidence: "ev",
				ct_hash: "ch",
				subject: "sub-1",
				kg: 0,
				options: {
					user_id: "u",
					rp_id: "id.example",
					exclude_credentials: [],
					algorithms: [-7],
				},
			},
		};
		const possession = {
			...common,
			nonce: "n2",
			purpose: purposes.possession,
			possession: {
				creation_hash: "h",
				key_jkt: "A".repeat(43),
				credential_id: "c",
				reservation_id: "r",
			},
		};
		const options = { ring: [ring.jwk], keys, issuer };
		const c = await signCompact(ring, creation, { typ: typs.statement });
		const p = await signCompact(ring, possession, { typ: typs.statement });
		expect(await readStatement(c, { ...options, purpose: "creation" })).toMatchObject({
			statement: creation,
		});
		expect(await readStatement(p, { ...options, purpose: "possession" })).toMatchObject({
			statement: possession,
		});
		expect(await readStatement(c, { ...options, purpose: "possession" })).toEqual({
			error: "payload",
		});
	});

	it("refuses one signed by another key, of another typ, or naming another issuer", async () => {
		const { ring, keys, t } = await world();
		const other = await signingKey("ES256", "core-1");
		const options = { purpose: "authorization" as const, ring: [ring.jwk], keys, issuer };
		expect(
			await readStatement(await signCompact(other, t, { typ: typs.statement }), options),
		).toEqual({ error: "signature" });
		expect(
			await readStatement(await signCompact(ring, t, { typ: typs.completion }), options),
		).toEqual({ error: "typ" });
		expect(
			await readStatement(
				await signCompact(ring, { ...t, iss: "https://other.example" }, { typ: typs.statement }),
				options,
			),
		).toEqual({ error: "issuer" });
	});

	it("refuses one naming another screen's keys: the Front swapped them", async () => {
		const { ring, keys, t } = await world();
		const theirs = await screenKeys();
		const options = { purpose: "authorization" as const, ring: [ring.jwk], keys, issuer };
		for (const swapped of [{ e_enc: theirs.eEnc }, { e_sig: theirs.eSig }]) {
			const compact = await signCompact(ring, { ...t, ...swapped }, { typ: typs.statement });
			expect(await readStatement(compact, options)).toEqual({ error: "keys" });
		}
	});

	it("refuses a purpose it does not know, answering and not throwing", async () => {
		const { ring, keys, t } = await world();
		const compact = await signCompact(ring, t, { typ: typs.statement });
		const options = { purpose: "toString", ring: [ring.jwk], keys, issuer } as never;
		expect(await readStatement(compact, options)).toEqual({ error: "payload" });
	});

	it("refuses a field the schema does not know", async () => {
		const { ring, keys, t } = await world();
		const compact = await signCompact(ring, { ...t, extra: 1 }, { typ: typs.statement });
		expect(
			await readStatement(compact, { purpose: "authorization", ring: [ring.jwk], keys, issuer }),
		).toEqual({ error: "payload" });
	});
});

describe("challengeOf", () => {
	it("is the SHA-256 of the use and the statement's compact bytes, as sdk-core-wire's input names them", async () => {
		const get = await challengeOf("a.b.c", "get");
		expect(Buffer.from(get).toString("base64url")).toBe(await digest("get\u0000a.b.c"));
		expect(Buffer.from(await challengeOf("a.b.c", "create"))).not.toEqual(Buffer.from(get));
	});
});
