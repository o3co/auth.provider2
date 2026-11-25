import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { claimsOf, es256, p256, relyingParty } from "./rp.ts";

const provider = {
	issuer: "https://issuer.example",
	tokenUrl: "https://issuer.example/oauth/token",
	parUrl: "https://issuer.example/oauth/par",
};

describe("the relying party's checks on an ID token", () => {
	const rp = relyingParty(provider, "rp-1", "https://rp.example/cb");
	const signer = p256();
	const keys = [{ ...signer.jwk, kid: "k1", alg: "ES256" }];
	const started = rp.authorization();
	const code = "the-code";
	const left = createHash("sha256").update(code).digest().subarray(0, 16).toString("base64url");
	const claims = {
		iss: provider.issuer,
		aud: "rp-1",
		exp: Math.floor(Date.now() / 1000) + 60,
		nonce: claimsOf(started.jar).nonce,
		c_hash: left,
	};
	const token = (header: object) => es256(signer.privateKey, header, claims);

	it("takes a token signed by a key of the provider's, every claim holding", () => {
		expect(rp.idTokenFaults(token({ alg: "ES256", kid: "k1" }), started, code, keys)).toEqual([]);
	});

	it("refuses a token of more than three parts, and one naming an algorithm its key does not take", () => {
		expect(
			rp.idTokenFaults(`${token({ alg: "ES256", kid: "k1" })}.extra`, started, code, keys),
		).toEqual(["form"]);
		expect(rp.idTokenFaults(token({ alg: "ES512", kid: "k1" }), started, code, keys)).toContain(
			"signature",
		);
		expect(rp.idTokenFaults(token({ alg: "RS256", kid: "k1" }), started, code, keys)).toContain(
			"signature",
		);
	});

	it("names the nonce, c_hash and audience that do not hold", () => {
		const other = rp.authorization();
		expect(rp.idTokenFaults(token({ alg: "ES256", kid: "k1" }), other, "x", keys)).toEqual([
			"nonce",
			"c_hash",
		]);
	});

	it("takes a callback only at its redirect URI, for the state it started with (R3)", () => {
		expect(
			rp.callbackFaults({ state: started.state, redirectUri: rp.redirectUri }, started),
		).toEqual([]);
		expect(
			rp.callbackFaults({ state: "other", redirectUri: "https://evil.example/cb" }, started),
		).toEqual(["redirect_uri", "state"]);
	});
});
