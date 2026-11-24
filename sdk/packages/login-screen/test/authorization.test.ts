import { hpke, purposes, typs } from "@mod/sdk-core-wire";
import { schemas as logSchemas, logTyps } from "@mod/transparency-wire";
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

describe("authorization.finish (A35)", () => {
	const otherDigest = (seed: string) => digest(`other-${seed}`);

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

	it("answers the code and ⑤'s record where the completion and its receipt both bind T, the assertion and the code", async () => {
		const { w, sealed, receipt, finish, code, receiptPayload } = await answered();
		expect(logSchemas.receipt.safeParse(receiptPayload).success).toBe(true);
		expect(await authorization.finish(w.read, sealed, receipt, finish)).toEqual({
			code,
			approval: { shard: "s1", n: 7 },
		});
	});

	it("refuses a receipt binding another T, another assertion or another code, each apart", async () => {
		for (const field of ["statement", "assertion", "code"] as const) {
			const { w, sealed, receipt, finish } = await answered(
				{},
				{},
				{ [field]: await otherDigest(field) },
			);
			expect(await authorization.finish(w.read, sealed, receipt, finish), field).toEqual({
				error: "receipt",
			});
		}
	});

	it("refuses a receipt of a record that is no approval", async () => {
		const { w, sealed, receipt, finish } = await answered({ kind: "start", approval: undefined });
		expect(await authorization.finish(w.read, sealed, receipt, finish)).toEqual({
			error: "receipt",
		});
	});

	it("refuses a receipt signed by a key not the log's, or of another typ", async () => {
		const { w, sealed, receipt, finish } = await answered();
		const stranger = await signingKey("ES256", "log-1");
		expect(
			await authorization.finish(w.read, sealed, receipt, { ...finish, log: [stranger.jwk] }),
		).toEqual({ error: "receipt" });
		const typed = await answered({}, { typ: typs.completion });
		expect(
			await authorization.finish(typed.w.read, typed.sealed, typed.receipt, typed.finish),
		).toEqual({ error: "receipt" });
	});

	it("refuses where the log's keys and the ring share a key, whatever else the key carries: the Core would sign its own receipt", async () => {
		const { w, sealed, receipt, finish } = await answered();
		for (const shared of [
			{ ...w.ring.jwk, kid: "log-shared" },
			{ ...w.ring.jwk, kid: "log-shared", n: "AQAB", use: "sig" },
		])
			expect(
				await authorization.finish(w.read, sealed, receipt, {
					...finish,
					log: [w.log.jwk, shared],
				}),
				JSON.stringify(shared),
			).toEqual({ error: "keys" });
	});

	it("takes keys with no identity, in both lists, for no shared key", async () => {
		const { w, sealed, receipt, finish, code } = await answered();
		const broken = { kty: "EC", crv: "P-256", x: "=", y: "=" };
		expect(
			await authorization.finish(w.read, sealed, receipt, {
				...finish,
				ring: [...finish.ring, broken],
				log: [...finish.log, broken],
			}),
		).toMatchObject({ code });
	});

	it("verifies with no key whose members are not canonical, so a padded twin of a ring key signs nothing", async () => {
		const { w, sealed, receipt, finish } = await answered();
		const padded = { ...w.log.jwk, x: `${w.log.jwk.x}=` };
		expect(
			await authorization.finish(w.read, sealed, receipt, { ...finish, log: [padded] }),
		).toEqual({ error: "receipt" });
	});

	it("passes the completion's refusal through before it reads the receipt", async () => {
		const { w, sealed, receipt, finish } = await answered();
		expect(
			await authorization.finish(w.read, sealed, receipt, { ...finish, aad: utf8("other") }),
		).toEqual({ error: "open" });
	});

	it("refuses a T it did not read", async () => {
		const { w, sealed, receipt, finish } = await answered();
		expect(await authorization.finish({ ...w.read }, sealed, receipt, finish)).toEqual({
			error: "statement",
		});
	});
});
