import { createHash } from "node:crypto";
import { tokenRules } from "@mod/authority-rules";
import type { IdTokenRequest } from "@mod/code-grant";
import { isUnavailable } from "@mod/kernel";
import type { Prepared } from "@mod/keys";
import { tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { type IdTokenParts, idTokenMaker } from "../id-token.ts";

const sha256 = (text: string) => createHash("sha256").update(text).digest("base64url");
const code = sha256("the-code");
const request: IdTokenRequest = {
	subject: "alice",
	clientId: "app",
	nonce: "n-0S6",
	amr: ["pop", "user"],
	scope: ["openid", "profile", "email"],
	session: "sid-1",
	code,
	esig: "e-sig-thumbprint",
	apr: { shard: "s1", n: 7 },
	approvedAt: 1_800_000_000_900,
};
const header: Prepared = {
	ring: "authority",
	header: { alg: "ES256", typ: "JWT", kid: "k1" },
	headerText: '{"alg":"ES256","typ":"JWT","kid":"k1"}',
	signatureLength: 64,
};
const attributes = { name: "Alice", email: "alice@example.com", email_verified: true, phone: "1" };

/** The parts over a holder that signs `header.claims` as its JWS, recording what it signed. */
function partsOf(over: Partial<IdTokenParts> = {}) {
	const signed: string[] = [];
	const parts: IdTokenParts = {
		keys: {
			prepare: (ring, typ) => ({ ...header, ring, header: { ...header.header, typ } }),
			sign: async (_prepared, payload) => {
				signed.push(new TextDecoder().decode(payload));
				return { kind: "signed", jws: `h.${signed.length}.s` };
			},
		},
		issuer: "https://as.example",
		lifetimeS: 3600,
		attributes: async () => ({ vouched: true, attributes }),
		asked: async () => undefined,
		...over,
	};
	return { parts, signed };
}

const made = async (over: Partial<IdTokenParts> = {}, asked: IdTokenRequest = request) => {
	const { parts, signed } = partsOf(over);
	const part = await idTokenMaker(parts).part(asked);
	const ready = await part.prepare(1_800_000_001_500);
	const jws = await part.sign(ready.prepared, "h.p1.s");
	return { part, ready, jws, signed, claims: JSON.parse(signed[0] ?? "{}") };
};

describe("a redemption's ID token", () => {
	it("carries its closed set of claims, the released ones beside them", async () => {
		const { part, claims, jws } = await made();
		expect(part.frame).toBe("idToken");
		expect(jws).toBe("h.1.s");
		expect(claims).toEqual({
			name: "Alice",
			email: "alice@example.com",
			email_verified: true,
			iss: "https://as.example",
			sub: "alice",
			aud: "app",
			azp: "app",
			iat: 1_800_000_001,
			exp: 1_800_000_001 + 3600,
			auth_time: 1_800_000_000,
			nonce: "n-0S6",
			sid: "sid-1",
			c_hash: tokenRules.idToken.cHash(code),
			amr: ["pop", "user"],
			esig: "e-sig-thumbprint",
			apr: { shard: "s1", n: 7 },
		});
	});

	it("names its digest as the log names a token's: its header's and claims' texts, the bytes it signs", async () => {
		const { ready, signed } = await made();
		const input = tokens.digestInput(header.headerText, signed[0] ?? "");
		if ("error" in input) throw new Error(input.error);
		expect(ready.digest).toBe(sha256(input.input));
	});

	it("carries the code's acr where it has one, and makes none whose approval is accepted after its iat", async () => {
		const { claims } = await made({}, { ...request, acr: "urn:acr:high" });
		expect(claims).toMatchObject({ acr: "urn:acr:high" });
		await expect(made({}, { ...request, approvedAt: 1_800_000_002_000 })).rejects.toSatisfy(
			isUnavailable,
		);
	});

	it("releases no released claim standing for one of its own, nor email_verified unvouched", async () => {
		const loud = { name: "x", sub: "mallory", iss: "https://evil", email_verified: true };
		const { claims } = await made({
			attributes: async () => ({ vouched: false, attributes: loud }),
		});
		expect(claims).toMatchObject({ sub: "alice", iss: "https://as.example", name: "x" });
		expect(claims).not.toHaveProperty("email_verified");
	});

	it("releases no table claim where neither source can say, and what the pin asks of the ID token", async () => {
		expect((await made({ attributes: async () => undefined })).claims).not.toHaveProperty("name");
		const asked = async (c: string) =>
			c === code
				? {
						names: [{ name: "picture", scope: "profile" }],
						constraints: [{ name: "name", value: "Bob" }],
					}
				: undefined;
		const { claims } = await made(
			{
				asked,
				attributes: async () => ({ vouched: true, attributes: { ...attributes, picture: "p" } }),
			},
			{ ...request, scope: ["openid", "profile"] },
		);
		expect(claims).toMatchObject({ picture: "p" });
		expect(claims).not.toHaveProperty("name");
	});

	it("fails the part where the attributes or the pin cannot be read, and is unavailable where signing was withdrawn", async () => {
		const gone = async () => {
			throw new Error("pin gone");
		};
		// Read when the part is asked, before the bundle starts: nothing is prepared.
		const failing = partsOf({ asked: gone });
		await expect(idTokenMaker(failing.parts).part(request)).rejects.toThrow("pin gone");
		const { parts } = partsOf({
			keys: { prepare: () => header, sign: async () => ({ kind: "withdrawn" }) },
		});
		const part = await idTokenMaker(parts).part(request);
		const ready = await part.prepare(1_800_000_001_500);
		await expect(part.sign(ready.prepared, "r")).rejects.toSatisfy(isUnavailable);
	});

	it("is prepared by the authority's ring under JWT", async () => {
		const rings: string[] = [];
		const { parts } = partsOf();
		const watched = {
			...parts,
			keys: {
				...parts.keys,
				prepare: (ring: "authority" | "core", typ: string) => (
					rings.push(`${ring} ${typ}`), parts.keys.prepare(ring, typ)
				),
			},
		};
		await (await idTokenMaker(watched).part(request)).prepare(1_800_000_001_500);
		expect(rings).toEqual(["authority JWT"]);
	});
});
