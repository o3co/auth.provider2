import { describe, expect, it } from "vitest";
import { logTyps, schemas, tokens } from "../src/contract.ts";

/** A P-256 public key and the RFC 7638 input of its thumbprint (members sorted, no whitespace). */
const vector = {
	jwk: {
		kty: "EC",
		crv: "P-256",
		x: "hQMu4HuOZ_d5_b08mXkYniVZiNIxPzQi4fi60fFaq-Y",
		y: "SpVrUw9eNN9M75NO5ohJORxBLqonn_JuAsldQoumFrg",
	},
	input:
		'{"crv":"P-256","kty":"EC","x":"hQMu4HuOZ_d5_b08mXkYniVZiNIxPzQi4fi60fFaq-Y","y":"SpVrUw9eNN9M75NO5ohJORxBLqonn_JuAsldQoumFrg"}',
} as const;
const d = (c: string) => c.repeat(43);
const apr = { shard: "s1", n: 7 };

describe("tokens.ecThumbprintInput", () => {
	it("gives the RFC 7638 input of a P-256 key: its members sorted, no whitespace", () => {
		expect(tokens.ecThumbprintInput(vector.jwk)).toBe(vector.input);
	});

	it("gives none for a key whose x or y is not 32 bytes in 43 characters, or not canonical", () => {
		for (const change of [
			{ x: vector.jwk.x.slice(0, 42) },
			{ x: `${vector.jwk.x}A` },
			{ y: `${vector.jwk.y.slice(0, 42)}h` },
			{ x: `${vector.jwk.x.slice(0, 42)}=` },
		])
			expect(tokens.ecThumbprintInput({ ...vector.jwk, ...change }), JSON.stringify(change)).toBe(
				undefined,
			);
	});

	it("gives none for a point off the curve, or a coordinate past the field", () => {
		expect(tokens.ecThumbprintInput({ ...vector.jwk, y: `${vector.jwk.y.slice(0, 42)}k` })).toBe(
			undefined,
		);
		// The point whose x is 0, and the same x + p: the curve's equation holds mod p for both.
		const zero = {
			...vector.jwk,
			x: "A".repeat(43),
			y: "ZkhceA4vg9ckM71dhKBrtlQcKvMdrocXKL-FahdPk_Q",
		};
		expect(tokens.ecThumbprintInput(zero)).toBeDefined();
		expect(
			tokens.ecThumbprintInput({ ...zero, x: "_____wAAAAEAAAAAAAAAAAAAAAD_______________8" }),
		).toBe(undefined);
	});

	it("gives none for another kind or curve, or a key with any other member", () => {
		for (const jwk of [
			{ ...vector.jwk, crv: "P-384" },
			{ ...vector.jwk, kty: "OKP" },
			{ ...vector.jwk, d: d("A") },
			{ ...vector.jwk, kid: "k" },
		])
			expect(tokens.ecThumbprintInput(jwk), JSON.stringify(jwk)).toBe(undefined);
	});
});

describe("the callback's proof (A38) and the ID token's evidence", () => {
	const proof = {
		iss: "https://id.example",
		client_id: "c1",
		state: "s",
		code_hash: d("c"),
		apr,
		iat: 1_700_000_000,
	};

	it("names the proof's typ apart from every other", () => {
		expect(logTyps.callback).toBe("callback+jwt");
	});

	it("reads a proof's header: ES256, its typ, and the screen's E_sig as a P-256 key", () => {
		const header = { alg: "ES256", typ: "callback+jwt", jwk: vector.jwk };
		expect(schemas.callbackHeader.parse(header)).toEqual(header);
		for (const change of [
			{ alg: "EdDSA" },
			{ typ: "approval+jwt" },
			{ jwk: { ...vector.jwk, x: "eA" } },
			{ kid: "k" },
		])
			expect(
				schemas.callbackHeader.safeParse({ ...header, ...change }).success,
				JSON.stringify(change),
			).toBe(false);
	});

	it("reads a proof's body: issuer, client, state, the code's hash, ⑤'s record and the device's time", () => {
		expect(schemas.callbackProof.parse(proof)).toEqual(proof);
		for (const change of [
			{ code_hash: "c" },
			{ apr: { shard: "s1" } },
			{ iat: -1 },
			{ c_hash: d("c") },
			{ state: "" },
		])
			expect(
				schemas.callbackProof.safeParse({ ...proof, ...change }).success,
				JSON.stringify(change),
			).toBe(false);
	});

	it("reads an ID token's evidence: the thumbprint of T's E_sig and the approval's record", () => {
		const evidence = { esig: d("t"), apr };
		expect(schemas.idTokenEvidence.parse(evidence)).toEqual(evidence);
		expect(schemas.idTokenEvidence.safeParse({ esig: "t", apr }).success).toBe(false);
		expect(schemas.idTokenEvidence.safeParse({ ...evidence, extra: 1 }).success).toBe(false);
	});
});

describe("an object a signer set signs", () => {
	it("reads as JWS JSON General Serialization: one payload, a signature per signer", () => {
		const signed = {
			payload: "eyJ2IjoxfQ",
			signatures: [
				{ protected: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImEifQ", signature: "c2ln" },
				{ protected: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImIifQ", signature: "c2ln" },
			],
		};
		expect(schemas.setSigned.parse(signed)).toEqual(signed);
		for (const bad of [
			{ ...signed, signatures: [] },
			{ ...signed, signatures: [signed.signatures[0], signed.signatures[0]] },
			{ ...signed, header: {} },
			{ payload: signed.payload, signature: "c2ln" },
			{ ...signed, payload: "a.b" },
		])
			expect(schemas.setSigned.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
	});
});

describe("a signer set's purpose", () => {
	it("names no set for the callback's proof, which E_sig signs", () => {
		const set = { v: 1, version: 1, keys: [{ kid: "k", key: vector.jwk }], required: 1 };
		expect(schemas.signerSet.safeParse({ ...set, purpose: "status" }).success).toBe(true);
		expect(schemas.signerSet.safeParse({ ...set, purpose: "callback" }).success).toBe(false);
	});
});

describe("the receivers' checks (R16–R18)", () => {
	it("names the frames a receipt check reads, and the faults of each check", () => {
		expect(tokens.checks.frames).toEqual(["idToken", "accessToken"]);
		expect(tokens.checks.receiptFaults).toEqual([
			"noReceipt",
			"receipt",
			"digest",
			"kind",
			"flow",
			"tooOld",
			"notYetChecked",
			"denied",
			"status",
		]);
		expect(tokens.checks.callbackFaults).toEqual(["proof", "key", "apr", "field"]);
		for (const frame of tokens.checks.frames) expect(tokens.frames).toContain(frame);
	});
});
