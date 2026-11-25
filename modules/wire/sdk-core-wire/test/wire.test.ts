import { describe, expect, it } from "vitest";
import {
	canonicalText,
	challengeInput,
	continuation,
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

describe("the answers' forms the Front carries", () => {
	const point = Buffer.concat([Buffer.of(4), Buffer.alloc(64, 7)]).toString("base64url");
	const ct = Buffer.alloc(17, 9).toString("base64url");

	it("reads a statement, a sealed value of a point and a ciphertext, and a nonce, each strict", () => {
		const { statement, sealed, nonce } = payloads.answers;
		expect(statement.parse({ statement: "a.b.c" })).toEqual({ statement: "a.b.c" });
		expect(sealed.parse({ sealed: { enc: point, ct } })).toEqual({ sealed: { enc: point, ct } });
		expect(nonce.parse({ nonce: "A".repeat(43) })).toEqual({ nonce: "A".repeat(43) });
		for (const [form, value] of [
			[statement, { statement: "a.b.c", extra: 1 }],
			[sealed, { sealed: { enc: point, ct }, extra: 1 }],
			[sealed, { sealed: { enc: point, ct, aad: "x" } }],
			[nonce, { nonce: "A".repeat(43), extra: 1 }],
		] as const)
			expect(form.safeParse(value).success, JSON.stringify(value)).toBe(false);
	});

	it("refuses an enc that is no uncompressed point of 65 bytes in its one spelling", () => {
		const bytes = Buffer.concat([Buffer.of(4), Buffer.alloc(64, 7)]);
		for (const enc of [
			Buffer.concat([Buffer.of(2), bytes.subarray(1)]).toString("base64url"),
			bytes.subarray(0, 64).toString("base64url"),
			Buffer.concat([bytes, Buffer.of(0)]).toString("base64url"),
			`${point}=`,
			`${point.slice(0, -1)}B`,
		])
			expect(payloads.answers.sealed.safeParse({ sealed: { enc, ct } }).success, enc).toBe(false);
	});

	it("refuses a ciphertext shorter than its tag, or not in its one spelling", () => {
		const tagOnly = Buffer.alloc(16).toString("base64url");
		expect(payloads.answers.sealed.safeParse({ sealed: { enc: point, ct: tagOnly } }).success).toBe(
			true,
		);
		for (const short of [
			Buffer.alloc(15).toString("base64url"),
			`${ct}=`,
			`${ct.slice(0, -1)}B`,
			"A".repeat(25),
		])
			expect(
				payloads.answers.sealed.safeParse({ sealed: { enc: point, ct: short } }).success,
				short,
			).toBe(false);
	});
});

describe("the completions' answers", () => {
	const base = { v: 1, iss: "https://id.example", iat: 1, exp: 2 };
	const hash = (c: string) => c.repeat(43);
	const approved = { ...base, t_hash: hash("E"), assertion_hash: hash("A") };
	const jkt = hash("A");

	it("takes the authorization's purpose and ⑤'s receipt where given, and none other", () => {
		const done = { ...base, t_hash: "t", assertion_hash: "a", code: "c" };
		expect(payloads.completion.safeParse(done).success).toBe(true);
		expect(
			payloads.completion.safeParse({ ...done, purpose: "authorization", receipt: "a.b.c" })
				.success,
		).toBe(true);
		for (const change of [{ purpose: "passkey-add" }, { receipt: "a.b" }])
			expect(
				payloads.completion.safeParse({ ...done, ...change }).success,
				JSON.stringify(change),
			).toBe(false);
	});

	it("reads a passkey-add's continued creation, its hashes each a SHA-256", () => {
		const { passkeyAdd } = payloads.completions;
		const add = { ...approved, purpose: "passkey-add", creation: "a.b.c" };
		expect(passkeyAdd.safeParse(add).success).toBe(true);
		for (const change of [
			{ creation: "x" },
			{ t_hash: "t" },
			{ assertion_hash: `${hash("A").slice(0, -1)}B` },
		])
			expect(passkeyAdd.safeParse({ ...add, ...change }).success, JSON.stringify(change)).toBe(
				false,
			);
	});

	it("reads a passkey-manage's keys, each credential once and 64 at most, each label 1 to 64 code points of no control, format or line separator", () => {
		const row = { credential_id: "c1", label: "Laptop", created_at: 0 };
		const list = (keys: unknown[], more: object = {}) =>
			payloads.completions.passkeyManage.safeParse({
				...approved,
				purpose: "passkey-manage",
				keys,
				...more,
			}).success;
		expect(list([])).toBe(true);
		expect(list([row, { ...row, credential_id: "c2", label: "鍵".repeat(64) }])).toBe(true);
		expect(list([row, { ...row, label: "Phone" }])).toBe(false);
		const many = Array.from({ length: 65 }, (_, i) => ({ ...row, credential_id: `c${i}` }));
		expect(list(many.slice(0, 64))).toBe(true);
		expect(list(many)).toBe(false);
		for (const label of [
			"",
			"x".repeat(65),
			"a\nb",
			"a\u0000",
			"a\u007f",
			"a\u202eb",
			"a\u200bb",
			"a\u2028b",
			"a\u2029b",
		])
			expect(list([{ ...row, label }]), JSON.stringify(label)).toBe(false);
		expect(list([{ ...row, created_at: -1 }])).toBe(false);
		expect(list([{ ...row, extra: 1 }])).toBe(false);
	});

	it("names what a rename's list answers, its stage, sequence and body's hash, so an earlier list is told apart", () => {
		const continued = { stage: "rename", seq: 2, body_hash: hash("I") };
		const list = (more: object) =>
			payloads.completions.passkeyManage.safeParse({
				...approved,
				purpose: "passkey-manage",
				keys: [],
				...more,
			}).success;
		expect(list({ continued })).toBe(true);
		for (const change of [
			{ stage: "delete" },
			{ seq: 0 },
			{ seq: 17 },
			{ seq: 1.5 },
			{ body_hash: "b" },
			{ extra: 1 },
		])
			expect(list({ continued: { ...continued, ...change } }), JSON.stringify(change)).toBe(false);
	});

	it("reads a key change: a key added under the first key or passkey-add, one deleted under passkey-manage, with what the Core adds", () => {
		const { keyChange } = payloads.completions;
		const add = { op: "add", credential_id: "c1", key_jkt: jkt };
		const del = { op: "delete", credential_id: "c1" };
		const read = (purpose: string, change: object, more: object = {}) =>
			keyChange.safeParse({ ...base, purpose, change, ...more }).success;
		expect(read("first-key", add)).toBe(true);
		expect(read("passkey-add", add)).toBe(true);
		const setSigned = JSON.stringify({
			payload: "e30",
			signatures: [{ protected: "e30", signature: "AA" }],
		});
		expect(
			read("passkey-manage", del, { receipt: "a.b.c", status: setSigned, stateOf: setSigned }),
		).toBe(true);
		// A status or a stateOf is a set's signed object, as JSON: a compact JWS, or JSON of no object, is not.
		for (const signed of ["d.e.f", "[]", "null", "{"])
			expect(read("passkey-manage", del, { status: signed }), signed).toBe(false);
		expect(read("passkey-manage", del, { stateOf: "g.h.i" })).toBe(false);
		expect(read("sign-up", add)).toBe(true);
		expect(read("sign-up", del)).toBe(false);
		expect(read("passkey-manage", add)).toBe(false);
		expect(read("first-key", del)).toBe(false);
		expect(read("passkey-add", del)).toBe(false);
		expect(read("first-key", { ...add, key_jkt: "x" })).toBe(false);
		expect(read("passkey-manage", { ...del, key_jkt: jkt })).toBe(false);
		expect(read("passkey-manage", { op: "rename", credential_id: "c1" })).toBe(false);
		expect(read("first-key", add, { receipt: "a.b" })).toBe(false);
		expect(read("authorization", add)).toBe(false);
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

	/** F1's creation: of sign-up's basis, no ciphertext hash and no account, named by `user_name`. */
	const { ct_hash: _ct, account: _account, ...noAccount } = creation.creation;
	const signUp = (options: Record<string, unknown> = { user_name: "Example 7f3a" }, more = {}) =>
		payloads.creation.safeParse({
			...creation,
			creation: {
				...noAccount,
				basis: "sign-up",
				options: { ...creation.creation.options, ...options },
				...more,
			},
		}).success;

	it("names a creation's account by account or user_name, one alone: the first key's path by account, sign-up's by user_name, passkey-add's by either", () => {
		expect(signUp()).toBe(true);
		for (const bad of ["", "   ", "x".repeat(65), "a\nb", "a\u202eb", 7])
			expect(signUp({ user_name: bad }), JSON.stringify(bad)).toBe(false);
		// Each basis with an account, a name, both or neither: the first key's path by account,
		// sign-up's by user_name, passkey-add's by either; both or neither on none.
		const { ct_hash: _, account: _a, ...neither } = creation.creation;
		const takes = {
			"": ["account"],
			"first-key": ["account"],
			"passkey-add": ["account", "user_name"],
			"sign-up": ["user_name"],
		};
		for (const [basis, names] of Object.entries(takes))
			for (const account of [false, true])
				for (const user_name of [false, true]) {
					const made = {
						...neither,
						...(basis === "" ? {} : { basis }),
						...(basis === "" || basis === "first-key" ? { ct_hash: "ct" } : {}),
						...(account ? { account: "a***" } : {}),
						options: { ...neither.options, ...(user_name ? { user_name: "N" } : {}) },
					};
					const one = account !== user_name && names.includes(account ? "account" : "user_name");
					expect(
						payloads.creation.safeParse({ ...creation, creation: made }).success,
						JSON.stringify({ basis, account, user_name }),
					).toBe(one);
				}
	});

	it("carries a ciphertext hash on the first key's path alone, by the creation's basis", () => {
		const { ct_hash: _, ...bare } = creation.creation;
		const with_ = (change: Record<string, unknown>, from: object = creation.creation) =>
			payloads.creation.safeParse({ ...creation, creation: { ...from, ...change } }).success;
		expect(with_({ basis: "first-key" })).toBe(true);
		expect(with_({ basis: "first-key" }, bare)).toBe(false);
		expect(with_({}, bare)).toBe(false);
		expect(signUp()).toBe(true);
		expect(signUp(undefined, { ct_hash: "ct" })).toBe(false);
		expect(with_({ basis: "passkey-add" }, bare)).toBe(true);
		expect(with_({ basis: "passkey-add" })).toBe(false);
		expect(with_({ basis: "other" })).toBe(false);
	});

	it("reads a passkey-add and a passkey-manage statement as the common fields, a nonce and their purpose alone", () => {
		for (const [schema, purpose] of [
			[payloads.passkeyAdd, purposes.passkeyAdd],
			[payloads.passkeyManage, purposes.passkeyManage],
		] as const) {
			expect(schema.safeParse({ ...common, purpose }).success, purpose).toBe(true);
			expect(schema.safeParse({ ...common, purpose: purposes.creation }).success).toBe(false);
			expect(schema.safeParse({ ...common, purpose, extra: 1 }).success).toBe(false);
			const { nonce: _, ...without } = common;
			expect(schema.safeParse({ ...without, purpose }).success).toBe(false);
		}
		expect([purposes.passkeyAdd, purposes.passkeyManage]).toEqual([
			"passkey-add",
			"passkey-manage",
		]);
	});

	it("signs every statement, T and the first key's alike, under one typ", () => {
		expect(typs.statement).toBe("approval+jwt");
	});
});

describe("the inputs a hash or a signature covers", () => {
	it("signs a recovery over the mail's nonce and the sealed request's digest, apart from every other input", () => {
		expect(firstKey.recoverInput("n", "d")).toBe(
			'{"digest":"d","nonce":"n","purpose":"first-key/recover"}',
		);
		expect(firstKey.recoverInput("n", "d")).not.toBe(firstKey.recoverInput("n", "e"));
		expect(firstKey.recoverInput("n", "d").startsWith("{")).toBe(true);
	});

	it("seals a completion under its purpose and the statement's hash, each purpose apart", () => {
		expect(hpke.completionAad("authorization", "h")).toBe(
			'{"h":"h","purpose":"completion/authorization"}',
		);
		const purposes = [
			"authorization",
			"first-key",
			"passkey-add",
			"passkey-manage",
			"sign-up",
		] as const;
		expect(new Set(purposes.map((p) => hpke.completionAad(p, "h"))).size).toBe(5);
		expect(hpke.completionAad("authorization", "h")).not.toBe(
			hpke.completionAad("authorization", "g"),
		);
	});

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
		expect(continuation.of("register", "h", 1, "b")).toBe(
			'{"body":"b","h":"h","seq":1,"stage":"register"}',
		);
	});

	it("signs each stage of a continuation apart, as ES256's raw r||s, and reads a delete's and a rename's body strict", () => {
		expect(continuation.stages).toEqual(["register", "delete", "rename"]);
		const inputs = continuation.stages.map((stage) => continuation.of(stage, "h", 1, "b"));
		expect(new Set(inputs).size).toBe(3);
		expect(continuation.signature).toEqual({
			alg: "ES256",
			form: "r||s",
			over: "UTF-8 of continuation.of",
		});
		const { delete: del, rename } = continuation.bodies;
		expect(del.safeParse({ credential_id: "AQID" }).success).toBe(true);
		expect(del.safeParse({ credential_id: "AQID", label: "x" }).success).toBe(false);
		expect(rename.safeParse({ credential_id: "AQID", label: "Laptop" }).success).toBe(true);
		for (const label of ["", "x".repeat(65), "a\u202eb", "a\nb"])
			expect(
				rename.safeParse({ credential_id: "AQID", label }).success,
				JSON.stringify(label),
			).toBe(false);
	});

	it("holds every word frozen, and names each sealing's info apart", () => {
		for (const words of [typs, purposes, hpke, hpke.info, payloads, firstKey, firstKey.stages])
			expect(Object.isFrozen(words)).toBe(true);
		const infos = Object.values(hpke.info);
		expect(new Set(infos).size).toBe(infos.length);
		expect(new Set(Object.values(typs)).size).toBe(Object.values(typs).length);
	});
});

describe("a sealed continuation's body (V24)", () => {
	const sig = `${"A".repeat(85)}A`;
	const bytes = (text: string) => Buffer.byteLength(text);

	it("seals a delete's and a rename's body with its signature, padded with spaces to one length, and reads it back", () => {
		expect(continuation.sealed).toEqual(["delete", "rename"]);
		const deleted = continuation.plainOf("delete", { credential_id: "AQID" }, sig);
		if (deleted === undefined) throw new Error("no plain");
		expect(bytes(deleted)).toBe(continuation.plainBytes);
		expect(deleted.trimEnd()).toBe(`{"body":{"credential_id":"AQID"},"sig":"${sig}"}`);
		expect(continuation.readPlain("delete", deleted)).toEqual({
			body: { credential_id: "AQID" },
			sig,
		});
		const renamed = continuation.plainOf("rename", { credential_id: "AQID", label: "鍵" }, sig);
		expect(renamed && continuation.readPlain("rename", renamed)).toEqual({
			body: { credential_id: "AQID", label: "鍵" },
			sig,
		});
	});

	it("fits the worst rename: a credential id of 1023 bytes and 64 characters escaped longest", () => {
		// A lone surrogate is refused; a quote escapes to two bytes, a four-byte character takes four.
		expect(
			continuation.bodies.rename.safeParse({ credential_id: "A", label: "\ud800" }).success,
		).toBe(false);
		for (const id of ["A", "AB", "A=", "a+b"])
			expect(continuation.bodies.delete.safeParse({ credential_id: id }).success, id).toBe(false);
		const worst = { credential_id: "A".repeat(1364), label: "😀".repeat(64) };
		const plain = continuation.plainOf("rename", worst, sig);
		expect(plain && bytes(plain)).toBe(continuation.plainBytes);
		expect(
			continuation.plainOf("rename", { ...worst, credential_id: "A".repeat(1365) }, sig),
		).toBeUndefined();
	});

	it("reads no text of another length, not canonical, of another stage's body or a signature of no shape", () => {
		const plain = continuation.plainOf("delete", { credential_id: "AQID" }, sig) ?? "";
		const pad = (text: string) => `${text}${" ".repeat(continuation.plainBytes - bytes(text))}`;
		for (const text of [
			plain.slice(0, -1),
			`${plain} `,
			pad(`{"sig":"${sig}","body":{"credential_id":"AQID"}}`),
			pad(`{"body":{"credential_id":"AQID"}, "sig":"${sig}"}`),
			pad(`{"body":{"credential_id":"AQID"},"sig":"${sig.slice(1)}"}`),
			pad(`{"body":{"credential_id":"AQID","label":"x"},"sig":"${sig}"}`),
		])
			expect(continuation.readPlain("delete", text), text.trimEnd()).toBeUndefined();
		expect(continuation.plainOf("delete", { credential_id: "AQID" }, "x")).toBeUndefined();
	});

	it("binds a sealed body to its stage, statement and sequence", () => {
		const aads = [
			continuation.aad("delete", "h", 1),
			continuation.aad("rename", "h", 1),
			continuation.aad("delete", "g", 1),
			continuation.aad("delete", "h", 2),
		];
		expect(new Set(aads).size).toBe(4);
		expect(aads[0]).toBe('{"h":"h","purpose":"continuation/delete","seq":1}');
		expect(hpke.info.continuation).toBe("auth.provider2/continuation/v1");
	});
});
