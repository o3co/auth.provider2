import { describe, expect, it } from "vitest";
import {
	canonicalText,
	challengeInput,
	continuationInput,
	firstKey,
	hpke,
	itemsFromJar,
	payloads,
	purposes,
	typs,
} from "../src/contract.ts";

const jar = {
	iss: "rp-1",
	aud: "https://id.example",
	iat: 1,
	exp: 61,
	jti: "j-1",
	client_id: "rp-1",
	redirect_uri: "https://rp.example/cb",
	response_type: "code",
	response_mode: "form_post",
	state: "s",
	scope: "openid",
	nonce: "n",
	code_challenge: "c",
	code_challenge_method: "S256",
	dpop_jkt: "k",
};
const key = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;

describe("the items T approves, from a JAR", () => {
	it("takes the items and the JAR's hash, and none of the envelope", () => {
		const read = itemsFromJar(jar, "h");
		expect("items" in read && read.items).toEqual({
			...Object.fromEntries(
				Object.entries(jar).filter(([k]) => !["iss", "aud", "iat", "exp", "jti"].includes(k)),
			),
			jar_hash: "h",
		});
	});

	it("takes prompt as the envelope's, never an item: the Core reads it before T is made", () => {
		const read = itemsFromJar({ ...jar, prompt: "login" }, "h");
		expect(read).toEqual(itemsFromJar(jar, "h"));
		expect("items" in read && "prompt" in read.items).toBe(false);
		for (const prompt of ["none", ["login"], 1, null])
			expect(itemsFromJar({ ...jar, prompt }, "h"), JSON.stringify(prompt)).toEqual(read);
	});

	it("refuses a claim outside the closed set, authorization_details among them", () => {
		expect(itemsFromJar({ ...jar, authorization_details: [] }, "h")).toEqual({
			error: "unknown_item:authorization_details",
		});
	});

	it("refuses a missing or empty item, and a mode or method it does not allow", () => {
		expect(itemsFromJar({ ...jar, state: "" }, "h")).toEqual({ error: "missing_item:state" });
		const { nonce: _, ...without } = jar;
		expect(itemsFromJar(without, "h")).toEqual({ error: "missing_item:nonce" });
		expect(itemsFromJar({ ...jar, response_mode: "query" }, "h")).toEqual({
			error: "item:response_mode",
		});
		expect(itemsFromJar({ ...jar, code_challenge_method: "plain" }, "h")).toEqual({
			error: "item:code_challenge_method",
		});
	});
});

describe("the payloads", () => {
	const statement = {
		v: 1,
		iss: "https://id.example",
		sid: "t-1",
		iat: 1,
		exp: 2,
		e_enc: "e",
		e_sig: key,
		purpose: purposes.authorization,
	};

	it("reads T with its approval, and refuses a field it does not know", () => {
		const read = itemsFromJar(jar, "h");
		const approval = "items" in read ? read.items : {};
		expect(payloads.statement.safeParse({ ...statement, approval }).success).toBe(true);
		expect(payloads.statement.safeParse({ ...statement, approval, extra: 1 }).success).toBe(false);
		expect(
			payloads.statement.safeParse({ ...statement, approval, purpose: purposes.creation }).success,
		).toBe(false);
	});

	it("reads a completion's answer, which names T's hash and the assertion's", () => {
		const completion = {
			v: 1,
			iss: "i",
			t_hash: "t",
			assertion_hash: "a",
			code: "c",
			iat: 1,
			exp: 2,
		};
		expect(payloads.completion.safeParse(completion).success).toBe(true);
		expect(payloads.completion.safeParse({ ...completion, t_hash: "" }).success).toBe(false);
	});

	it("reads the first key's opened requests, a password only where the deployment asks one", () => {
		expect(payloads.startPlain.safeParse({ identifier: "a@x.example" }).success).toBe(true);
		expect(
			payloads.startPlain.safeParse({ identifier: "a@x.example", password: "p" }).success,
		).toBe(true);
		expect(payloads.mailPlain.safeParse({ token: "t", identifier: "a", code: "c" }).success).toBe(
			true,
		);
		expect(payloads.mailPlain.safeParse({ token: "t", identifier: "a" }).success).toBe(false);
	});
});

describe("②'s answer to an authorization's start", () => {
	const answer = {
		statement: "eyJh.eyJi.c2ln",
		challenge: "A".repeat(43),
		create: false,
	};

	it("reads T, its get challenge and whether a passkey may be made first", () => {
		expect(payloads.answers.authorization.parse(answer)).toEqual(answer);
		expect(payloads.answers.authorization.parse({ ...answer, create: true }).create).toBe(true);
	});

	it("refuses a statement that is no compact JWS, a challenge that is no SHA-256, a create that is no boolean, and any other field", () => {
		for (const change of [
			{ statement: "a.b" },
			{ statement: "a.b.c.d" },
			{ statement: "a.b+.c" },
			{ challenge: "A".repeat(42) },
			{ challenge: `${"A".repeat(42)}B` },
			{ challenge: `${"A".repeat(42)}=` },
			{ create: "false" },
			{ purpose: "authorization" },
		])
			expect(
				payloads.answers.authorization.safeParse({ ...answer, ...change }).success,
				JSON.stringify(change),
			).toBe(false);
		const { create: _, ...without } = answer;
		expect(payloads.answers.authorization.safeParse(without).success).toBe(false);
	});
});

describe("the first key's statements", () => {
	const common = {
		v: 1,
		iss: "https://id.example",
		sid: "c-1",
		iat: 1,
		exp: 2,
		e_enc: "e",
		e_sig: { kty: "EC", crv: "P-256", x: "x", y: "y" },
		nonce: "n",
	};
	const creation = {
		...common,
		purpose: purposes.creation,
		creation: {
			account: "a***",
			evidence: "ev",
			ct_hash: "ct",
			subject: "s-1",
			kg: 0,
			options: {
				user_id: "u",
				rp_id: "id.example",
				exclude_credentials: [],
				algorithms: [-7, -8],
			},
		},
	};

	it("binds a creation to the key generation it was signed for, a whole number from 0", () => {
		expect(payloads.creation.safeParse(creation).success).toBe(true);
		const { kg: _, ...without } = creation.creation;
		expect(payloads.creation.safeParse({ ...creation, creation: without }).success).toBe(false);
		expect(
			payloads.creation.safeParse({ ...creation, creation: { ...creation.creation, kg: -1 } })
				.success,
		).toBe(false);
	});

	it("signs every statement, T and the first key's alike, under one typ", () => {
		expect(typs.statement).toBe("approval+jwt");
	});
});

describe("the inputs a hash or a signature covers", () => {
	it("builds JSON canonically, keys sorted and undefined members left out", () => {
		expect(canonicalText({ b: 1, a: [2, { d: undefined, c: "x" }] })).toBe(
			'{"a":[2,{"c":"x"}],"b":1}',
		);
	});

	it("binds a challenge to its use and the statement, and the evidence to the token, with a separator", () => {
		expect(challengeInput("T", "get")).toBe("get\u0000T");
		expect(challengeInput("T", "create")).not.toBe(challengeInput("T", "get"));
		expect(firstKey.evidenceInput("tok")).toBe("first-key-token\u0000tok");
	});

	it("binds a sealed request to its stage, nonce and the screen's keys, whatever order they come in", () => {
		const aad = firstKey.aad("start", "n", "e", key);
		expect(aad).toBe(
			'{"e_enc":"e","e_sig":{"x":"x","y":"y"},"nonce":"n","purpose":"first-key/start"}',
		);
		expect(firstKey.aad("mail", "n", "e", key)).not.toBe(aad);
		expect(continuationInput("h", 1, "b")).toBe('{"body":"b","h":"h","seq":1,"stage":"register"}');
	});

	it("holds every word frozen, and names each sealing's info apart", () => {
		for (const words of [typs, purposes, hpke, hpke.info, payloads, firstKey, firstKey.stages])
			expect(Object.isFrozen(words)).toBe(true);
		const infos = Object.values(hpke.info);
		expect(new Set(infos).size).toBe(infos.length);
		expect(new Set(Object.values(typs)).size).toBe(Object.values(typs).length);
	});
});
