import type { Keys, VerifyResult } from "@mod/keys";
import { describe, expect, it } from "vitest";
import { idTokenTyp } from "../../id-token/id-token.ts";
import { hintReader } from "../hint.ts";

const issuer = "https://as.example";
const valid = (claims: Record<string, unknown>): VerifyResult => ({ kind: "valid", claims });
const reader = (answer: VerifyResult) => {
	const asked: [string, string, string][] = [];
	const verify: Keys["verify"] = async (ring, token, typ) => {
		asked.push([ring, token, typ]);
		return answer;
	};
	return { asked, read: hintReader({ verify, issuer }) };
};
const idToken = { iss: issuer, sub: "alice", aud: "app", exp: 1, iat: 0 };

describe("an ID token given back as a hint (OIDC Core §3.1.2.1, §3.1.2.2)", () => {
	it("names its subject where the authority's ring verifies it as an ID token of this issuer for the client", async () => {
		const { asked, read } = reader(valid(idToken));
		expect(await read.subjectOf("h.p.s", "app")).toEqual({ subject: "alice" });
		expect(asked).toEqual([["authority", "h.p.s", idTokenTyp]]);
	});

	it("takes one long expired (§3.1.2.2: its exp is not checked), and an audience list naming the client", async () => {
		const { read } = reader(valid({ ...idToken, exp: 0, aud: ["other", "app"] }));
		expect(await read.subjectOf("h.p.s", "app")).toEqual({ subject: "alice" });
	});

	it("refuses one the ring does not verify, of any reason: a key past its expires-at among them", async () => {
		for (const reason of ["malformed", "typ", "kid_unknown", "kid_expired", "signature"] as const) {
			const { read } = reader({ kind: "invalid", reason });
			expect(await read.subjectOf("h.p.s", "app"), reason).toEqual({
				refused: `the id_token_hint is not an ID token of this issuer (${reason})`,
			});
		}
	});

	it("refuses one of another issuer, for another client, or naming no subject", async () => {
		const cases: [Record<string, unknown>, string][] = [
			[{ ...idToken, iss: "https://other.example" }, "the id_token_hint is of another issuer"],
			[{ ...idToken, aud: "other" }, "the id_token_hint is for another client"],
			[{ ...idToken, aud: ["other"] }, "the id_token_hint is for another client"],
			[{ ...idToken, aud: undefined }, "the id_token_hint is for another client"],
			[{ ...idToken, aud: [7] }, "the id_token_hint is for another client"],
			[{ ...idToken, sub: "" }, "the id_token_hint names no subject"],
			[{ ...idToken, sub: 7 }, "the id_token_hint names no subject"],
		];
		for (const [claims, refused] of cases) {
			const { read } = reader(valid(claims));
			expect(await read.subjectOf("h.p.s", "app"), JSON.stringify(claims)).toEqual({ refused });
		}
	});
});
