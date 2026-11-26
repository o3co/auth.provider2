import { hpke, purposes, typs } from "@mod/sdk-core-wire";
import { schemas as logSchemas, logTyps, tokens } from "@mod/transparency-wire";
import { describe, expect, it } from "vitest";
import { authorization } from "../src/authorization.ts";
import { digest, utf8 } from "../src/bytes.ts";
import { sealTo } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";
const jarPayload = {
	iss: "c1",
	aud: issuer,
	iat: 1,
	exp: 9,
	jti: "j1",
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
};
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jarOf = (payload: unknown) => `${b64({ alg: "ES256", typ: typs.jar })}.${b64(payload)}.sig`;

async function world() {
	const ring = await signingKey("ES256", "core-1");
	const log = await signingKey("ES256", "log-1");
	const keys = await screenKeys();
	const jar = jarOf(jarPayload);
	const { iss: _i, aud: _a, iat: _t, exp: _e, jti: _j, ...items } = jarPayload;
	const approval = { ...items, jar_hash: await digest(jar) };
	const t = {
		v: 1,
		iss: issuer,
		sid: "st-1",
		iat: 1,
		exp: 2,
		e_enc: keys.eEnc,
		e_sig: keys.eSig,
		purpose: purposes.authorization,
		approval,
	};
	const tCompact = await signCompact(ring, t, { typ: typs.statement });
	const options = { ring: [ring.jwk], log: [log.jwk], keys, issuer };
	const read = await authorization.read(tCompact, jar, options);
	if ("error" in read) throw new Error(read.error);
	return { ring, log, keys, jar, t, tCompact, options, read: read.t };
}

describe("authorization.read", () => {
	it("reads T where its items are exactly what the JAR the screen holds gives", async () => {
		const { jar, t, tCompact, options } = await world();
		const read = await authorization.read(tCompact, jar, options);
		expect(read).toMatchObject({ t: { statement: t, compact: tCompact } });
		if ("t" in read) expect(Object.isFrozen(read.t.statement.approval)).toBe(true);
	});

	it("refuses T whose items differ from the JAR's in any item", async () => {
		const { ring, t, tCompact, options, jar } = await world();
		const otherJar = jarOf({ ...jarPayload, scope: "openid email" });
		expect(await authorization.read(tCompact, otherJar, options)).toEqual({ error: "items" });
		const changed = await signCompact(
			ring,
			{ ...t, approval: { ...t.approval, state: "other" } },
			{ typ: typs.statement },
		);
		expect(await authorization.read(changed, jar, options)).toEqual({ error: "items" });
	});

	it("reads T asking a claim by {} where its JAR asks it by null, and refuses T holding a null", async () => {
		const { ring, t, options } = await world();
		const jar = jarOf({ ...jarPayload, claims: { id_token: { email: null } } });
		const approval = {
			...t.approval,
			claims: { id_token: { email: {} } },
			jar_hash: await digest(jar),
		};
		const asked = await signCompact(ring, { ...t, approval }, { typ: typs.statement });
		expect(await authorization.read(asked, jar, options)).toMatchObject({ t: { compact: asked } });
		const held = { ...approval, claims: { id_token: { email: null } } };
		const nulled = await signCompact(ring, { ...t, approval: held }, { typ: typs.statement });
		expect(await authorization.read(nulled, jar, options)).toEqual({ error: "payload" });
	});

	it("refuses a JAR of the same claims whose bytes differ: its hash is another", async () => {
		const { tCompact, options, jar } = await world();
		expect(await authorization.read(tCompact, `${jar}x`, options)).toEqual({ error: "items" });
	});

	it("refuses a JAR that is no compact JWS, or whose claims sdk-core-wire's rule refuses", async () => {
		const { tCompact, options } = await world();
		expect(await authorization.read(tCompact, "nojar", options)).toEqual({ error: "jar" });
		expect(await authorization.read(tCompact, jarOf({ ...jarPayload, extra: 1 }), options)).toEqual(
			{ error: "jar" },
		);
		expect(await authorization.read(tCompact, `${b64({})}.${b64([1])}.s`, options)).toEqual({
			error: "jar",
		});
	});

	it("passes a statement's refusal through", async () => {
		const { jar, t, options } = await world();
		const other = await signingKey("ES256", "core-1");
		const tCompact = await signCompact(other, t, { typ: typs.statement });
		expect(await authorization.read(tCompact, jar, options)).toEqual({ error: "signature" });
	});
});

describe("authorization.assertionOptions", () => {
	it("asks the authenticator for the read T's get challenge, with user verification", async () => {
		const { read, tCompact } = await world();
		const asked = await authorization.assertionOptions(read, { rpId: "id.example" });
		if ("error" in asked) throw new Error(asked.error);
		expect(Buffer.from(asked.options.challenge as Uint8Array).toString("base64url")).toBe(
			await digest(`get\u0000${tCompact}`),
		);
		expect(asked.options).toMatchObject({ rpId: "id.example", userVerification: "required" });
		expect(asked.options.allowCredentials).toBeUndefined();
	});

	it("names the credentials the caller gives", async () => {
		const { read } = await world();
		const asked = await authorization.assertionOptions(read, {
			rpId: "id.example",
			credentials: ["AQID"],
		});
		expect(asked).toMatchObject({
			options: { allowCredentials: [{ type: "public-key", id: Uint8Array.of(1, 2, 3) }] },
		});
	});

	it("refuses credentials given empty, or any one not a credential id: it never widens to any credential", async () => {
		const { read } = await world();
		for (const credentials of [
			[],
			[""],
			["AQID", "not base64url!"],
			["AQJ"],
			Array<string>(1),
			["AQID", ...Array<string>(1)],
		])
			expect(
				await authorization.assertionOptions(read, { rpId: "id.example", credentials }),
				JSON.stringify(credentials),
			).toEqual({ error: "credentials" });
	});

	it("refuses a T it did not read", async () => {
		const { read } = await world();
		expect(await authorization.assertionOptions({ ...read }, { rpId: "id.example" })).toEqual({
			error: "statement",
		});
	});
});

/** A completion sealed to T's E_enc and ⑤'s receipt for it, the receipt and its approval changed where given. */
async function answered(
	receiptChange: Record<string, unknown> = {},
	receiptHeader = {},
	approvalChange: Record<string, string> = {},
) {
	const w = await world();
	const assertion = utf8('{"a":1}');
	const code = "code-1";
	const completion = {
		v: 1,
		iss: issuer,
		t_hash: await digest(w.tCompact),
		assertion_hash: await digest(assertion),
		code,
		iat: 1,
		exp: 2,
	};
	const aad = utf8("aad");
	const sealed = await sealTo(
		Buffer.from(w.keys.eEnc, "base64url"),
		utf8(hpke.info.completion),
		aad,
		utf8(await signCompact(w.ring, completion, { typ: typs.completion })),
	);
	const approval = {
		statement: await digest(w.tCompact),
		assertion: await digest(assertion),
		code: await digest(code),
	};
	const receiptPayload = {
		v: 1,
		iss: "log",
		id: "r-1",
		writer: { role: "core", instance: "i", image: "img", generation: 1 },
		kind: "approval",
		flow: { of: "subject", id: "sub-1" },
		position: 3,
		shard: "s1",
		n: 7,
		acceptedAt: 1000,
		plaintextDigest: await digest("p"),
		approval: { ...approval, ...approvalChange },
		...receiptChange,
	};
	const receipt = await signCompact(w.log, receiptPayload, {
		typ: logTyps.receipt,
		...receiptHeader,
	});
	const finish = { ...w.options, assertion, aad };
	return { w, sealed, receipt, finish, code, receiptPayload, approval };
}

describe("authorization.finish (A35)", () => {
	const otherDigest = (seed: string) => digest(`other-${seed}`);

	it("answers the code and ⑤'s record where the completion and its receipt both bind T, the assertion and the code", async () => {
		const { w, sealed, receipt, finish, code, receiptPayload } = await answered();
		expect(logSchemas.receipt.safeParse(receiptPayload).success).toBe(true);
		expect(
			await authorization.finish(w.read, sealed, { ...finish, level: "log", receipt: receipt }),
		).toEqual({
			code,
			approval: { shard: "s1", n: 7 },
		});
	});

	it("answers the code alone at L0, no receipt read, the completion still held to T, the assertion and its additional data", async () => {
		const { w, sealed, finish, code } = await answered();
		const { log: _log, ...completionOnly } = finish;
		const done = await authorization.finish(w.read, sealed, { ...completionOnly, level: "L0" });
		expect(done).toEqual({ code });
		// No record to name: the callback's proof needs ⑤'s, which only a receipt gives.
		expect(await authorization.callbackProof(w.read, done as never, w.keys, 0)).toEqual({
			error: "level",
		});
		expect(
			await authorization.finish(w.read, sealed, {
				...completionOnly,
				level: "L0",
				aad: utf8("other"),
			}),
		).toEqual({ error: "open" });
		expect(
			await authorization.finish({ ...w.read }, sealed, { ...completionOnly, level: "L0" }),
		).toEqual({
			error: "statement",
		});
		expect(
			await authorization.finish(w.read, sealed, {
				...completionOnly,
				level: "L0",
				assertion: utf8("another assertion"),
			}),
		).toEqual({ error: "assertion" });
		// The level is named, never left out, and the log's inputs given whole.
		for (const bad of [
			completionOnly,
			{ ...completionOnly, level: "L1" },
			{ ...finish, level: "log" },
			{ ...finish, level: "log", receipt: "r", log: [] },
			{ ...finish, level: "log", receipt: "r", log: "keys" },
		])
			expect(
				await authorization.finish(w.read, sealed, bad as never),
				JSON.stringify((bad as { level?: unknown }).level),
			).toEqual({
				error: "checks",
			});
	});

	it("refuses a receipt binding another T, another assertion or another code, each apart", async () => {
		for (const field of ["statement", "assertion", "code"] as const) {
			const { w, sealed, receipt, finish } = await answered(
				{},
				{},
				{ [field]: await otherDigest(field) },
			);
			expect(
				await authorization.finish(w.read, sealed, { ...finish, level: "log", receipt: receipt }),
				field,
			).toEqual({
				error: "receipt",
			});
		}
	});

	it("refuses a receipt of a record that is no approval", async () => {
		const { w, sealed, receipt, finish } = await answered({ kind: "start", approval: undefined });
		expect(
			await authorization.finish(w.read, sealed, { ...finish, level: "log", receipt: receipt }),
		).toEqual({
			error: "receipt",
		});
	});

	it("refuses a receipt signed by a key not the log's, or of another typ", async () => {
		const { w, sealed, receipt, finish } = await answered();
		const stranger = await signingKey("ES256", "log-1");
		expect(
			await authorization.finish(w.read, sealed, {
				...finish,
				level: "log",
				receipt: receipt,
				log: [stranger.jwk],
			}),
		).toEqual({ error: "receipt" });
		const typed = await answered({}, { typ: typs.completion });
		expect(
			await authorization.finish(typed.w.read, typed.sealed, {
				...typed.finish,
				level: "log",
				receipt: typed.receipt,
			}),
		).toEqual({ error: "receipt" });
	});

	it("refuses where the log's keys and the ring share a key, whatever else the key carries: the Core would sign its own receipt", async () => {
		const { w, sealed, receipt, finish } = await answered();
		for (const shared of [
			{ ...w.ring.jwk, kid: "log-shared" },
			{ ...w.ring.jwk, kid: "log-shared", n: "AQAB", use: "sig" },
		])
			expect(
				await authorization.finish(w.read, sealed, {
					...finish,
					level: "log",
					receipt,
					log: [w.log.jwk, shared],
				}),
				JSON.stringify(shared),
			).toEqual({ error: "keys" });
	});

	it("takes keys with no identity, in both lists, for no shared key", async () => {
		const { w, sealed, receipt, finish, code } = await answered();
		const broken = { kty: "EC", crv: "P-256", x: "=", y: "=" };
		expect(
			await authorization.finish(w.read, sealed, {
				...finish,
				level: "log",
				receipt,
				ring: [...finish.ring, broken],
				log: [...finish.log, broken],
			}),
		).toMatchObject({ code });
	});

	it("verifies with no key whose members are not canonical, so a padded twin of a ring key signs nothing", async () => {
		const { w, sealed, receipt, finish } = await answered();
		const padded = { ...w.log.jwk, x: `${w.log.jwk.x}=` };
		expect(
			await authorization.finish(w.read, sealed, {
				...finish,
				level: "log",
				receipt: receipt,
				log: [padded],
			}),
		).toEqual({ error: "receipt" });
	});

	it("passes the completion's refusal through before it reads the receipt", async () => {
		const { w, sealed, receipt, finish } = await answered();
		expect(
			await authorization.finish(w.read, sealed, {
				...finish,
				level: "log",
				receipt: receipt,
				aad: utf8("other"),
			}),
		).toEqual({ error: "open" });
	});

	it("refuses a T it did not read", async () => {
		const { w, sealed, receipt, finish } = await answered();
		expect(
			await authorization.finish({ ...w.read }, sealed, {
				...finish,
				level: "log",
				receipt: receipt,
			}),
		).toEqual({
			error: "statement",
		});
	});
});

describe("authorization.callbackProof (A38)", () => {
	/** T read, and what `finish` gave for it. */
	async function taken() {
		const { w, sealed, receipt, finish } = await answered();
		const given = await authorization.finish(w.read, sealed, {
			...finish,
			level: "log",
			receipt: receipt,
		});
		if ("error" in given) throw new Error(given.error);
		return { ...w, done: given };
	}

	it("signs with E_sig the proof the RP reads against the ID token: the request, the code's hash and ⑤'s record", async () => {
		const { read, keys, t, done } = await taken();
		const made = await authorization.callbackProof(read, done, keys, 1_700_000_000_123);
		if ("error" in made) throw new Error(made.error);
		const [h, p, s] = made.proof.split(".");
		const header = JSON.parse(Buffer.from(h ?? "", "base64url").toString());
		const body = JSON.parse(Buffer.from(p ?? "", "base64url").toString());
		expect(logSchemas.callbackHeader.parse(header)).toEqual({
			alg: "ES256",
			typ: logTyps.callback,
			jwk: keys.eSig,
		});
		expect(logSchemas.callbackProof.parse(body)).toEqual({
			iss: issuer,
			client_id: t.approval.client_id,
			state: t.approval.state,
			code_hash: await digest("code-1"),
			apr: { shard: "s1", n: 7 },
			iat: 1_700_000_000,
		});
		const key = await crypto.subtle.importKey(
			"jwk",
			{ ...keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				key,
				Buffer.from(s ?? "", "base64url"),
				utf8(`${h}.${p}`),
			),
		).toBe(true);
		expect(tokens.ecThumbprintInput(keys.eSig)).toBeDefined();
	});

	it("refuses a T it did not read, or keys other than the ones T names", async () => {
		const { read, keys, done } = await taken();
		expect(await authorization.callbackProof({ ...read }, done, keys, 0)).toEqual({
			error: "statement",
		});
		expect(await authorization.callbackProof(read, done, await screenKeys(), 0)).toEqual({
			error: "keys",
		});
	});

	it("refuses a code and record not what finish gave for this T: written by the caller, or given for another T", async () => {
		const { read, keys, done } = await taken();
		expect(await authorization.callbackProof(read, { ...done }, keys, 0)).toEqual({
			error: "finish",
		});
		const other = await taken();
		expect(await authorization.callbackProof(read, other.done, keys, 0)).toEqual({
			error: "finish",
		});
	});
});
