import type { Client } from "@mod/clients";
import { typs } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { jarVerified } from "../jar.ts";

const now = 1_800_000_000_000;
const issuer = "https://issuer.example";
const client = { id: "c1" } as Client;
const good = {
	iss: "c1",
	client_id: "c1",
	aud: issuer,
	jti: "j1",
	nbf: now / 1000,
	exp: now / 1000 + 60,
};

/** The check over a signature that answers the JAR's own claims where its client signed it with the JAR's typ. */
const verifying = (signer = "c1") => ({
	assertion: {
		verifySignedBy: async (c: Client, jar: string, typ: string) =>
			typ === typs.jar && c.id === signer
				? { kind: "signed" as const, claims: JSON.parse(jar) }
				: { kind: "refused" as const, reason: "signature" },
	},
	issuer,
	maxLifetimeS: 600,
	now: () => now,
});
const verified = (claims: object, signer?: string) =>
	jarVerified(verifying(signer), client, JSON.stringify(claims));

describe("a JAR verified as its client's", () => {
	it("answers its claims, jti and exp where its client signed it for this issuer", async () => {
		expect(await verified(good)).toEqual({
			kind: "verified",
			claims: good,
			jti: "j1",
			exp: good.exp,
		});
		expect(await verified({ ...good, aud: ["https://other.example", issuer] })).toMatchObject({
			kind: "verified",
		});
		// The longest life is taken to the second.
		expect(await verified({ ...good, exp: now / 1000 + 600 })).toMatchObject({ kind: "verified" });
	});

	it("is refused, saying why, where any of its parts is not its client's own for now", async () => {
		const reason = async (claims: object, signer?: string) => {
			const answer = await verified(claims, signer);
			return answer.kind === "refused" ? answer.reason : answer.kind;
		};
		expect(await reason(good, "c2")).toBe("signature");
		expect(await reason({ ...good, iss: "c2" })).toMatch(/not its client's/);
		expect(await reason({ ...good, client_id: "c2" })).toMatch(/not its client's/);
		expect(await reason({ ...good, aud: "https://other.example" })).toMatch(/not for this issuer/);
		expect(await reason({ ...good, aud: ["https://other.example"] })).toMatch(
			/not for this issuer/,
		);
		expect(await reason({ ...good, jti: "" })).toBe("the request names no jti");
		const { jti: _none, ...noJti } = good;
		expect(await reason(noJti)).toBe("the request names no jti");
		expect(await reason({ ...good, exp: "soon" })).toBe("the request names no exp");
		expect(await reason({ ...good, exp: now / 1000 })).toMatch(/expired/);
		expect(await reason({ ...good, exp: now / 1000 + 601 })).toMatch(/longer than is taken/);
	});

	it("takes an nbf at most 60 minutes past and a life at most 60 minutes from it (FAPI 2.0 Message Signing §5.3.1)", async () => {
		const reason = async (claims: object) => {
			const answer = await verified(claims);
			return answer.kind === "refused" ? answer.reason : answer.kind;
		};
		const { nbf: _none, ...noNbf } = good;
		expect(await reason(noNbf)).toBe("the request names no nbf");
		expect(await reason({ ...good, nbf: "now" })).toBe("the request names no nbf");
		// The suite's case: an nbf 70 minutes ago.
		expect(await reason({ ...good, nbf: now / 1000 - 70 * 60 })).toBe(
			"the request's nbf is more than 60 minutes past",
		);
		// 60 minutes past is not too far past, though an exp not yet past lives longer than 60 minutes from it.
		expect(await reason({ ...good, nbf: now / 1000 - 60 * 60 })).toBe(
			"the request lives more than 60 minutes from its nbf",
		);
		expect(await reason({ ...good, nbf: now / 1000 - 60 * 60 - 1 })).toBe(
			"the request's nbf is more than 60 minutes past",
		);
		// An nbf 50 minutes past with an exp 11 minutes on lives 61 minutes from it.
		expect(await reason({ ...good, nbf: now / 1000 - 50 * 60, exp: now / 1000 + 11 * 60 })).toBe(
			"the request lives more than 60 minutes from its nbf",
		);
		expect(await reason({ ...good, nbf: now / 1000 - 50 * 60, exp: now / 1000 + 10 * 60 })).toBe(
			"verified",
		);
		// An nbf a few seconds ahead is the signature check's to judge against the clock skew.
		expect(await reason({ ...good, nbf: now / 1000 + 8 })).toBe("verified");
	});

	it("answers the first part that fails, in the order the client, the issuer, jti, exp and nbf, then the time", async () => {
		const answer = await verified({ ...good, iss: "c2", aud: "https://other.example", jti: "" });
		expect(answer).toEqual({ kind: "refused", reason: "the request is not its client's" });
		expect(await verified({ aud: "https://other.example", jti: "" }, "c2")).toEqual({
			kind: "refused",
			reason: "signature",
		});
		const late = await verified({ ...good, aud: "https://other.example", exp: now / 1000 });
		expect(late).toEqual({ kind: "refused", reason: "the request is not for this issuer" });
	});
});
