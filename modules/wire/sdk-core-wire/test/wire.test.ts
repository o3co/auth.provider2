import { describe, expect, it } from "vitest";
import {
	canonicalText,
	challengeInput,
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

	it("writes the request_uri a start under PAR named as T's item, and none by value; a JAR carrying one yields none", () => {
		const pushed = itemsFromJar(jar, "h", "urn:ietf:params:oauth:request_uri:abc");
		expect(pushed).toMatchObject({
			items: { request_uri: "urn:ietf:params:oauth:request_uri:abc" },
		});
		const byValue = itemsFromJar(jar, "h");
		if (!("items" in byValue)) throw new Error(byValue.error);
		expect("request_uri" in byValue.items).toBe(false);
		expect(itemsFromJar({ ...jar, request_uri: "urn:x" }, "h")).toEqual({
			error: "refused_item:request_uri",
		});
		expect(itemsFromJar(jar, "h", "")).toMatchObject({ error: "item:request_uri" });
	});

	it("takes prompt as the envelope's, never an item: the Core reads it before T is made", () => {
		const read = itemsFromJar({ ...jar, prompt: "login" }, "h");
		expect(read).toEqual(itemsFromJar(jar, "h"));
		expect("items" in read && "prompt" in read.items).toBe(false);
		for (const prompt of ["none", ["login"], 1, null])
			expect(itemsFromJar({ ...jar, prompt }, "h"), JSON.stringify(prompt)).toEqual(read);
	});

	it("reads a claim asked by null, at an ID token's or userinfo's request, as asked by {} (OIDC Core §5.5.1)", () => {
		const asked = {
			id_token: { email: null },
			userinfo: { name: null, given_name: { essential: true } },
		};
		const read = itemsFromJar({ ...jar, claims: asked }, "h");
		expect("items" in read && read.items.claims).toEqual({
			id_token: { email: {} },
			userinfo: { name: {}, given_name: { essential: true } },
		});
		// The same items as the {} spelling, and the JAR's own payload left as it was.
		expect(read).toEqual(
			itemsFromJar(
				{
					...jar,
					claims: {
						id_token: { email: {} },
						userinfo: { name: {}, given_name: { essential: true } },
					},
				},
				"h",
			),
		);
		expect(asked.id_token.email).toBeNull();
	});

	it("refuses any null left in claims, where none reads as a request asked in the default manner", () => {
		for (const claims of [
			null,
			{ id_token: null },
			{ other: null },
			{ id_token: { email: { essential: true, purpose: null } } },
			{ id_token: { email: { value: null } } },
			{ id_token: { foo: { x: null } } },
			{ id_token: { nickname: [null] } },
			{ verified_claims: { claims: { given_name: null } } },
		]) {
			expect(itemsFromJar({ ...jar, claims }, "h"), JSON.stringify(claims)).toEqual({
				error: "item:claims",
			});
		}
		// T's own schema refuses a statement whose claims hold a null, as the screen reads it.
		const made = itemsFromJar({ ...jar, claims: { id_token: { email: null } } }, "h");
		if (!("items" in made)) throw new Error(made.error);
		const held = { ...made.items, claims: { id_token: { email: null } } };
		expect(payloads.statement.shape.approval.safeParse(held).success).toBe(false);
		expect(payloads.statement.shape.approval.safeParse(made.items).success).toBe(true);
	});

	it("refuses claims that are no JSON object, as OpenID Connect Core §5.5 writes the parameter, at the JAR and in T alike", () => {
		for (const claims of [5, "x", true, [], [{ id_token: {} }]]) {
			expect(itemsFromJar({ ...jar, claims }, "h"), JSON.stringify(claims)).toEqual({
				error: "item:claims",
			});
		}
		const made = itemsFromJar({ ...jar, claims: {} }, "h");
		if (!("items" in made)) throw new Error(made.error);
		expect(made.items.claims).toEqual({});
		// An object of no prototype is an object too.
		const bare = Object.assign(Object.create(null), { id_token: {} });
		expect("items" in itemsFromJar({ ...jar, claims: bare }, "h")).toBe(true);
		// T's own schema refuses a statement whose claims are no object, as the screen reads it.
		for (const claims of [5, [], "x", true])
			expect(payloads.statement.shape.approval.safeParse({ ...made.items, claims }).success).toBe(
				false,
			);
	});

	it("writes T for a JAR of items alone as it always did, byte for byte", () => {
		const read = itemsFromJar({ ...jar, claims: { id_token: { email: null } } }, "h");
		if (!("items" in read)) throw new Error(read.error);
		expect(canonicalText(read.items)).toBe(
			'{"claims":{"id_token":{"email":{}}},"client_id":"rp-1","code_challenge":"c",' +
				'"code_challenge_method":"S256","dpop_jkt":"k","jar_hash":"h","nonce":"n",' +
				'"redirect_uri":"https://rp.example/cb","response_mode":"form_post",' +
				'"response_type":"code","scope":"openid","state":"s"}',
		);
	});

	it("takes display, ui_locales, claims_locales, login_hint and acr_values of any value, and holds none of them in T", () => {
		const plain = itemsFromJar(jar, "h");
		const names = ["display", "ui_locales", "claims_locales", "login_hint", "acr_values"];
		for (const name of names)
			for (const value of ["page", "", " ", 7, null, true, [], ["x"], { a: null }])
				expect(
					itemsFromJar({ ...jar, [name]: value }, "h"),
					`${name} ${JSON.stringify(value)}`,
				).toEqual(plain);
		const all = Object.freeze({
			...jar,
			display: "popup",
			ui_locales: "ja en",
			claims_locales: "ja",
			login_hint: "a@b",
			acr_values: "urn:a urn:b",
		});
		const before = JSON.stringify(all);
		expect(itemsFromJar(all, "h")).toEqual(plain);
		expect(JSON.stringify(all)).toBe(before);
	});

	it("holds in T the subject an id_token_hint reads as (hint_sub), never the hint, and refuses one that reads as none", () => {
		const b64 = (text: string) => Buffer.from(text).toString("base64url");
		const hintOf = (payload: string, head = b64('{"alg":"ES256"}'), sig = "c2ln") =>
			`${head}.${b64(payload)}.${sig}`;
		const read = itemsFromJar(
			{ ...jar, id_token_hint: hintOf('{"sub":"alice","aud":"rp-1"}') },
			"h",
		);
		if (!("items" in read)) throw new Error(read.error);
		expect(read.items.hint_sub).toBe("alice");
		expect("id_token_hint" in read.items).toBe(false);
		// A subject of any text, read from its UTF-8 bytes.
		expect(
			itemsFromJar({ ...jar, id_token_hint: hintOf('{"sub":"ユーザー/1 😀 é"}') }, "h"),
		).toMatchObject({ items: { hint_sub: "ユーザー/1 😀 é" } });
		// UTF-8 read strictly: an overlong, a surrogate, one past U+10FFFF, a cut or stray byte is none.
		const raw = (bad: readonly number[]) =>
			`${b64("{}")}.${Buffer.concat([Buffer.from('{"sub":"a'), Buffer.from(bad), Buffer.from('"}')]).toString("base64url")}.c2ln`;
		for (const bad of [
			[0xc0, 0x80],
			[0xed, 0xa0, 0x80],
			[0xf4, 0x90, 0x80, 0x80],
			[0xe3, 0x81],
			[0x80],
			[0xff],
			// 3- and 4-byte overlongs, past the lead byte's class.
			[0xe0, 0x80, 0x80],
			[0xf0, 0x80, 0x80, 0x80],
			// A lead byte followed by no continuation.
			[0xc3, 0x41],
			[0xe3, 0x81, 0x41],
		])
			expect(itemsFromJar({ ...jar, id_token_hint: raw(bad) }, "h"), String(bad)).toEqual({
				error: "item:id_token_hint",
			});
		// A payload that reads, under a form that is no compact JWS: an empty header or signature, 2, 4 or 5 parts.
		const body = b64('{"sub":"alice"}');
		for (const id_token_hint of [
			`.${body}.c2ln`,
			`${b64("{}")}.${body}.`,
			`${b64("{}")}.${body}`,
			`${b64("{}")}.${body}.c2ln.x`,
			`${b64("{}")}.${body}.c2ln.x.y`,
		])
			expect(itemsFromJar({ ...jar, id_token_hint }, "h"), id_token_hint).toEqual({
				error: "item:id_token_hint",
			});
		// A header or signature in the alphabet but not its one spelling (bits past the end set).
		for (const id_token_hint of [
			`${b64("{}")}.${body}.c3`,
			`eyJ.${body}.c2ln`,
			`${b64("{}")}.${body}.c2lu1`,
		])
			expect(itemsFromJar({ ...jar, id_token_hint }, "h"), id_token_hint).toEqual({
				error: "item:id_token_hint",
			});
		// A byte order mark is no JSON (RFC 8259 §8.1): the payload's text read as it is, the mark kept, refused.
		const marked = `${b64("{}")}.${Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"sub":"alice"}')]).toString("base64url")}.c2ln`;
		expect(itemsFromJar({ ...jar, id_token_hint: marked }, "h")).toEqual({
			error: "item:id_token_hint",
		});
		const plain = itemsFromJar(jar, "h");
		expect("items" in plain && "hint_sub" in plain.items).toBe(false);
		// An encrypted one (five parts) is the client's to decrypt first (§3.1.2.1); no other form reads.
		for (const id_token_hint of [
			"a.b.c.d.e",
			"a.b",
			"a..c",
			".b.c",
			"a.b.",
			"",
			" a.b.c",
			1,
			null,
			["a.b.c"],
			hintOf('{"aud":"rp-1"}'),
			hintOf('{"sub":""}'),
			hintOf('{"sub":7}'),
			hintOf('["alice"]'),
			hintOf('"alice"'),
			hintOf("not json"),
			`${b64("{}")}.${b64('{"sub":"alice"}')}=.c2ln`,
			`${b64("{}")}.${Buffer.from([0xff, 0xfe]).toString("base64url")}.c2ln`,
			`${b64("{}")}.eyJzdWIiOiJhIn1.c2ln`,
		])
			expect(itemsFromJar({ ...jar, id_token_hint }, "h"), JSON.stringify(id_token_hint)).toEqual({
				error: "item:id_token_hint",
			});
	});

	it("takes max_age of a whole number of seconds, as a number or its digits, and holds it nowhere in T", () => {
		const plain = itemsFromJar(jar, "h");
		for (const max_age of [0, 60, 86400, "0", "3600"])
			expect(itemsFromJar({ ...jar, max_age }, "h"), JSON.stringify(max_age)).toEqual(plain);
	});

	it("refuses a max_age that is no whole number of seconds", () => {
		for (const max_age of [
			-1,
			1.5,
			Number.NaN,
			2 ** 53,
			"",
			" ",
			"x",
			"-1",
			"1.5",
			"1e3",
			" 1",
			"0x10",
			null,
			true,
			[],
			[1],
			{},
		])
			expect(itemsFromJar({ ...jar, max_age }, "h"), JSON.stringify(max_age)).toEqual({
				error: "item:max_age",
			});
		// Before T's own items' rules, after the items it must carry.
		expect(itemsFromJar({ ...jar, response_mode: "query", max_age: "x" }, "h")).toEqual({
			error: "item:max_age",
		});
		// The items it must carry are named first, as before.
		const { nonce: _, ...without } = jar;
		expect(itemsFromJar({ ...without, max_age: "x" }, "h")).toEqual({
			error: "missing_item:nonce",
		});
	});

	it("refuses the known items refused, each by its rule: request and request_uri (RFC 9101 §4), authorization_details (A25)", () => {
		for (const name of ["request", "request_uri", "authorization_details"])
			for (const value of ["x", [], {}, null])
				expect(itemsFromJar({ ...jar, [name]: value }, "h"), name).toEqual({
					error: `refused_item:${name}`,
				});
		// Before an item missing, as an unknown claim was.
		const { nonce: _, ...without } = jar;
		expect(itemsFromJar({ ...without, request: "x" }, "h")).toEqual({
			error: "refused_item:request",
		});
	});

	it("takes a claim no rule names and holds nothing of it in T, byte for byte as the same JAR without it (RFC 6749 §3.1)", () => {
		const plain = itemsFromJar(jar, "h");
		if (!("items" in plain)) throw new Error(plain.error);
		const bytes = canonicalText(plain.items);
		// T's own names the JAR cannot set (jar_hash, hint_sub), case variants of items and refused items, and the rest.
		const names = ["other", "x_vendor", "", "__proto__", "constructor", "\ud800", "ITEMS", "Scope"];
		names.push("registration", "client_secret", "jar_hash", "hint_sub", "Resource", "Claims");
		names.push("Request_URI", "REQUEST", "Authorization_Details");
		const values: unknown[] = [
			1,
			"x",
			null,
			[],
			{ scope: "admin" },
			{ resource: "https://evil.example" },
		];
		values.push(
			{ claims: { id_token: { email: {} } } },
			{ id_token: { sub: { value: "mallory" } } },
		);
		for (const name of names)
			for (const value of values) {
				const payload = Object.fromEntries([...Object.entries(jar), [name, value]]);
				const read = itemsFromJar(payload, "h");
				if (!("items" in read)) throw new Error(`${JSON.stringify(name)}: ${read.error}`);
				expect(canonicalText(read.items), `${JSON.stringify(name)} ${JSON.stringify(value)}`).toBe(
					bytes,
				);
			}
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

	it("reads a passkey-manage's keys, each credential once and 16 at most, each label 1 to 64 code points of no control, format or line separator", () => {
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
		const many = Array.from({ length: 17 }, (_, i) => ({ ...row, credential_id: `c${i}` }));
		expect(list(many.slice(0, 16))).toBe(true);
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
			{ refused: "last" },
			{ seq: 0 },
			{ seq: 17 },
			{ seq: 1.5 },
			{ body_hash: "b" },
			{ extra: 1 },
		])
			expect(list({ continued: { ...continued, ...change } }), JSON.stringify(change)).toBe(false);
	});

	it("names a delete the Core did not take, its reason sealed in the list: last, used or unknown", () => {
		const refused = { stage: "delete", seq: 1, body_hash: hash("Q"), refused: "last" };
		const list = (continued: object) =>
			payloads.completions.passkeyManage.safeParse({
				...approved,
				purpose: "passkey-manage",
				keys: [],
				continued,
			}).success;
		for (const why of ["last", "used", "unknown"])
			expect(list({ ...refused, refused: why }), why).toBe(true);
		for (const change of [{ refused: "other" }, { refused: undefined }, { seq: 17 }, { extra: 1 }])
			expect(list({ ...refused, ...change }), JSON.stringify(change)).toBe(false);
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

	it("excludes 15 credentials at most, a passkey-add's for a subject of 16 keys being refused before", () => {
		const excluding = (count: number) =>
			payloads.creation.safeParse({
				...creation,
				creation: {
					...creation.creation,
					options: {
						...creation.creation.options,
						exclude_credentials: Array.from({ length: count }, (_, i) => `c${i}`),
					},
				},
			}).success;
		expect([excluding(15), excluding(16)]).toEqual([true, false]);
	});

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

	it("pads a passkey-add's or passkey-manage's completion to the bucket its longest credential ID chooses, so its length tells no count or label", () => {
		const b64 = (text: string) => Buffer.from(text).toString("base64url");
		const label = "\u{1F600}".repeat(64);
		const iss = `https://${"x".repeat(hpke.completionLimits.issuerChars - 8)}`;
		const times = { iat: 9_999_999_999, exp: 9_999_999_999 };
		const approvedOf = { v: 1, iss, t_hash: "h".repeat(43), assertion_hash: "a".repeat(43) };
		/** A compact JWS of the payload, its kid 128 characters and its signature an RSA key's of 8192 bits. */
		const jws = (typ: string, payload: object) =>
			`${b64(JSON.stringify({ alg: "PS256", kid: "k".repeat(hpke.completionLimits.kidChars), typ }))}.${b64(JSON.stringify(payload))}.${"s".repeat(Math.ceil(hpke.completionLimits.rsaBits / 6))}`;
		const id = (bytes: number) => "A".repeat(Math.ceil((bytes * 4) / 3));
		const list = (count: number, idBytes: number) =>
			jws(typs.completion, {
				...approvedOf,
				purpose: "passkey-manage",
				keys: Array.from({ length: count }, () => ({
					credential_id: id(idBytes),
					label,
					created_at: 9_999_999_999_999,
				})),
				continued: { stage: "rename", seq: 16, body_hash: "b".repeat(43) },
				...times,
			});
		const added = (idBytes: number) =>
			jws(typs.completion, {
				...approvedOf,
				purpose: "passkey-add",
				creation: jws(typs.statement, {
					v: 1,
					iss,
					sid: "s".repeat(43),
					...times,
					e_enc: `B${"A".repeat(86)}`,
					e_sig: { kty: "EC", crv: "P-256", x: "x".repeat(43), y: "y".repeat(43) },
					nonce: "n".repeat(43),
					purpose: "creation",
					creation: {
						account: "a".repeat(320),
						basis: "passkey-add",
						evidence: "e".repeat(43),
						subject: "s".repeat(255),
						kg: 99,
						options: {
							user_id: "u".repeat(86),
							user_name: label,
							rp_id: "r".repeat(253),
							exclude_credentials: Array.from({ length: 15 }, () => id(idBytes)),
							algorithms: [-7, -8, -257, -37],
						},
					},
				}),
				...times,
			});
		expect(hpke.completionBuckets).toEqual([16_384, 45_056]);
		expect(hpke.completionLimits).toEqual({ issuerChars: 256, kidChars: 128, rsaBits: 8192 });
		expect(Object.isFrozen(hpke.completionLimits)).toBe(true);
		// The longest ID alone chooses: 128 bytes or less the smaller, whatever the count or labels.
		for (const [plain, longest, bucket] of [
			[list(16, 128), 128, 16_384],
			[list(1, 128), 128, 16_384],
			[added(128), 128, 16_384],
			[list(1, 129), 129, 45_056],
			[list(16, 1023), 1023, 45_056],
			[added(1023), 1023, 45_056],
		] as const)
			expect(hpke.paddedCompletion(plain, longest)?.length, `${longest} ${plain.length}`).toBe(
				bucket,
			);
		// One that does not fit its bucket is none, so the sealing side does not sign it.
		expect(hpke.paddedCompletion(list(16, 1023), 128)).toBeUndefined();
		expect(hpke.paddedCompletion("a.b.c".padEnd(45_057, "c"), 1023)).toBeUndefined();
		expect(hpke.paddedCompletion("not a jws", 0)).toBeUndefined();
		// A miscount never falls into the smaller bucket: an ID length is a whole number of bytes.
		for (const miscount of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY])
			expect(hpke.paddedCompletion("a.b.c", miscount), String(miscount)).toBeUndefined();
		for (const [longest, bucket] of [
			[0, 16_384],
			[1023, 45_056],
		] as const) {
			const padded = hpke.paddedCompletion("a.b.c", longest) ?? "";
			expect([padded.length, hpke.unpaddedCompletion(padded)]).toEqual([bucket, "a.b.c"]);
		}
		// Read back only at a bucket's length, a JWS then spaces alone.
		const small = hpke.paddedCompletion("a.b.c", 0) ?? "";
		for (const text of [
			"a.b.c",
			`${small} `,
			small.slice(1),
			`a.b .c${" ".repeat(16_378)}`,
			`a.b.c\t${" ".repeat(16_378)}`,
			`a.b.c\n${" ".repeat(16_378)}`,
			`${" ".repeat(16_379)}a.b.c`,
		])
			expect(hpke.unpaddedCompletion(text), JSON.stringify(text.slice(0, 8))).toBeUndefined();
		expect(Object.isFrozen(hpke.completionBuckets)).toBe(true);
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
	});

	it("holds every word frozen, and names each sealing's info apart", () => {
		for (const words of [typs, purposes, hpke, hpke.info, payloads, firstKey, firstKey.stages])
			expect(Object.isFrozen(words)).toBe(true);
		const infos = Object.values(hpke.info);
		expect(new Set(infos).size).toBe(infos.length);
		// A continuation's sealed body is sealed under this info; its words are continuation-wire's.
		expect(hpke.info.continuation).toBe("auth.provider2/continuation/v1");
		expect(new Set(Object.values(typs)).size).toBe(Object.values(typs).length);
	});
});
