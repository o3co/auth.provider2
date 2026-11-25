import { readFileSync } from "node:fs";
import { continuations } from "@mod/continuation-wire";
import { passkeyThumbprintInput } from "@mod/passkey-key-wire";
import { canonicalText, hpke, purposes, typs, firstKey as words } from "@mod/sdk-core-wire";
import { describe, expect, it } from "vitest";
import { digest, utf8 } from "../src/bytes.ts";
import { firstKey } from "../src/first-key.ts";
import { openSealed, sealTo } from "../src/hpke.ts";
import { screenKeys } from "../src/keys.ts";
import { signCompact, signingKey } from "./fixtures.ts";

const issuer = "https://id.example";
const nonce = "n".repeat(43);
const text = (bytes: Uint8Array | undefined) =>
	bytes ? new TextDecoder().decode(bytes) : undefined;

/** The Core's sealing key pair, as a test holds it. */
async function coreSealing() {
	const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
		"deriveBits",
	]);
	return { pair, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

async function world() {
	const ring = await signingKey("ES256", "core-1");
	const keys = await screenKeys();
	const core = await coreSealing();
	const options = { ring: [ring.jwk], keys, issuer, sealingKey: core.point };
	return { ring, keys, core, options };
}

/** The keys both sides read alike (sdk-core-wire's vectors): each one's SPKI, COSE algorithm and thumbprint. */
const vectors = (
	JSON.parse(
		readFileSync(
			new URL("../test/keys.vectors.json", import.meta.resolve("@mod/passkey-key-wire")),
			"utf8",
		),
	) as { accepted: { name: string; alg: number; spki: string; jkt: string }[] }
).accepted.map((v) => ({ name: v.name, alg: v.alg, spki: Buffer.from(v.spki, "hex"), jkt: v.jkt }));

/** A fresh P-256 key as a passkey's `create()` gives it: the SPKI bytes, ES256, and its thumbprint. */
async function passkey() {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
	]);
	const { crv, kty, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return {
		name: "fresh ES256",
		alg: -7,
		spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
		jkt: await digest(passkeyThumbprintInput({ crv, kty, x, y }) ?? ""),
	};
}

describe("firstKey.start", () => {
	it("seals the identifier (and password) to the Core under the start's info and additional data", async () => {
		const { keys, core, options } = await world();
		const sealed = await firstKey.start(
			{ identifier: "a@example", password: "pw" },
			nonce,
			options,
		);
		if ("error" in sealed) throw new Error(sealed.error);
		const aad = utf8(words.aad("start", nonce, keys.eEnc, keys.eSig));
		const opened = await openSealed(core.pair, sealed.sealed, utf8(hpke.info.firstKeyRequest), aad);
		expect(JSON.parse(text(opened) ?? "")).toEqual({ identifier: "a@example", password: "pw" });
	});

	it("refuses a plaintext the protocol's schema refuses", async () => {
		const { options } = await world();
		expect(await firstKey.start({ identifier: "" }, nonce, options)).toEqual({ error: "plain" });
	});
});

describe("firstKey.openCode", () => {
	it("opens the start's answer sealed to the screen under the code's info and the start's additional data", async () => {
		const { keys, options } = await world();
		const aad = utf8(words.aad("start", nonce, keys.eEnc, keys.eSig));
		const point = Buffer.from(keys.eEnc, "base64url");
		const sealed = await sealTo(
			point,
			utf8(hpke.info.firstKeyCode),
			aad,
			utf8('{"code":"123456"}'),
		);
		expect(await firstKey.openCode(sealed, nonce, options)).toEqual({ code: "123456" });
		const other = await sealTo(point, utf8(hpke.info.completion), aad, utf8('{"code":"1"}'));
		expect(await firstKey.openCode(other, nonce, options)).toEqual({ error: "open" });
		const extra = await sealTo(
			point,
			utf8(hpke.info.firstKeyCode),
			aad,
			utf8('{"code":"1","x":1}'),
		);
		expect(await firstKey.openCode(extra, nonce, options)).toEqual({ error: "payload" });
	});
});

async function mailed() {
	const w = await world();
	const sent = await firstKey.mail(
		{ token: "tok", identifier: "a@example", code: "123456" },
		nonce,
		w.options,
	);
	if ("error" in sent) throw new Error(sent.error);
	const creationPayload = {
		v: 1,
		iss: issuer,
		sid: "st-1",
		iat: 1,
		exp: 2,
		e_enc: w.keys.eEnc,
		e_sig: w.keys.eSig,
		nonce: "cn",
		purpose: purposes.creation,
		creation: {
			account: "a***@example",
			evidence: await digest(`first-key-token\u0000tok`),
			ct_hash: await digest(Buffer.concat([sent.mail.sealed.enc, sent.mail.sealed.ct])),
			subject: "sub-1",
			kg: 0,
			options: {
				user_id: "dXNlcg",
				rp_id: "id.example",
				exclude_credentials: ["AQID"],
				algorithms: [-7, -8, -257],
			},
		},
	};
	const sign = (payload: unknown) => signCompact(w.ring, payload, { typ: typs.statement });
	const creationCompact = await sign(creationPayload);
	return { ...w, mail: sent.mail, creationPayload, creationCompact, sign };
}

describe("firstKey.mail", () => {
	it("seals the token, identifier and code under the mail's additional data, and keeps the evidence and the ciphertext's hash", async () => {
		const { keys, core, mail } = await mailed();
		const aad = utf8(words.aad("mail", nonce, keys.eEnc, keys.eSig));
		const opened = await openSealed(core.pair, mail.sealed, utf8(hpke.info.firstKeyRequest), aad);
		expect(JSON.parse(text(opened) ?? "")).toEqual({
			token: "tok",
			identifier: "a@example",
			code: "123456",
		});
		expect(mail.evidence).toBe(await digest("first-key-token\u0000tok"));
		expect(mail.ctHash).toBe(await digest(Buffer.concat([mail.sealed.enc, mail.sealed.ct])));
		expect(Object.isFrozen(mail.sealed)).toBe(true);
	});
});

describe("firstKey.recover", () => {
	it("signs the mail's nonce and its sealed request's digest with the keys it was sealed under", async () => {
		const { keys, mail } = await mailed();
		const recovered = await firstKey.recover(mail);
		if ("error" in recovered) throw new Error(recovered.error);
		const ctHash = await digest(Buffer.concat([mail.sealed.enc, mail.sealed.ct]));
		expect({ nonce: recovered.nonce, digest: recovered.digest }).toEqual({ nonce, digest: ctHash });
		const publicKey = await crypto.subtle.importKey(
			"jwk",
			{ ...keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		const signature = Buffer.from(recovered.sig, "base64url");
		expect(signature).toHaveLength(64);
		const input = canonicalText({ purpose: "first-key/recover", nonce, digest: ctHash });
		expect(words.recoverInput(nonce, ctHash)).toBe(input);
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				publicKey,
				signature,
				utf8(input),
			),
		).toBe(true);
	});

	it("recovers only a mail this page sealed", async () => {
		const { mail } = await mailed();
		expect(await firstKey.recover({ ...mail })).toEqual({ error: "mail" });
	});
});

describe("firstKey.readCreation", () => {
	it("reads the creation whose evidence and ciphertext hash are the screen's own", async () => {
		const { mail, creationCompact, creationPayload, options } = await mailed();
		expect(await firstKey.readCreation(creationCompact, mail, options)).toMatchObject({
			creation: { statement: creationPayload, compact: creationCompact },
		});
	});

	it("refuses one whose evidence or ciphertext hash is another: the Front rewrapped another's token", async () => {
		const { mail, creationPayload, sign, options } = await mailed();
		/** The ciphertext alone, its encapsulated key left out: a hash of part of the request is another. */
		const ctAlone = (m: typeof mail) => m.sealed.ct;
		for (const [change, error] of [
			[{ evidence: await digest("first-key-token\u0000theirs") }, "evidence"],
			[{ ct_hash: await digest("other") }, "ciphertext"],
			[{ ct_hash: await digest(ctAlone(mail)) }, "ciphertext"],
		] as const) {
			const compact = await sign({
				...creationPayload,
				creation: { ...creationPayload.creation, ...change },
			});
			expect(await firstKey.readCreation(compact, mail, options), error).toEqual({ error });
		}
	});

	it("reads one of no basis or the first key's, and refuses another path's: a creation passkey-add or sign-up made is not this mail's", async () => {
		const { mail, creationPayload, sign, options } = await mailed();
		const withBasis = (creation: Record<string, unknown>) =>
			sign({ ...creationPayload, creation: { ...creationPayload.creation, ...creation } });
		expect(
			await firstKey.readCreation(await withBasis({ basis: "first-key" }), mail, options),
		).toHaveProperty("creation");
		const { ct_hash: _, ...withoutCiphertext } = creationPayload.creation;
		for (const basis of ["passkey-add", "sign-up"]) {
			const compact = await sign({ ...creationPayload, creation: { ...withoutCiphertext, basis } });
			expect(await firstKey.readCreation(compact, mail, options), basis).toEqual({
				error: "basis",
			});
		}
	});

	it("refuses a mail it did not seal, and passes a statement's refusal through", async () => {
		const { mail, creationCompact, creationPayload, options } = await mailed();
		expect(await firstKey.readCreation(creationCompact, { ...mail }, options)).toEqual({
			error: "mail",
		});
		const other = await signingKey("ES256", "core-1");
		const forged = await signCompact(other, creationPayload, { typ: typs.statement });
		expect(await firstKey.readCreation(forged, mail, options)).toEqual({ error: "signature" });
	});
});

async function created() {
	const m = await mailed();
	const read = await firstKey.readCreation(m.creationCompact, m.mail, m.options);
	if ("error" in read) throw new Error(read.error);
	return { ...m, creation: read.creation };
}

describe("firstKey.createOptions", () => {
	it("asks for a passkey of the algorithms the creation offers, in its order, for its subject, its create challenge, user verification and a resident key required", async () => {
		const { creation, creationCompact } = await created();
		const asked = await firstKey.createOptions(creation, { rpName: "Example" });
		if ("error" in asked) throw new Error(asked.error);
		const { options } = asked;
		expect(Buffer.from(options.challenge as Uint8Array).toString("base64url")).toBe(
			await digest(`create\u0000${creationCompact}`),
		);
		expect(options.rp).toEqual({ id: "id.example", name: "Example" });
		expect(Buffer.from(options.user.id as Uint8Array).toString()).toBe("user");
		expect(options.user.name).toBe("a***@example");
		expect(options.pubKeyCredParams).toEqual([
			{ type: "public-key", alg: -7 },
			{ type: "public-key", alg: -8 },
			{ type: "public-key", alg: -257 },
		]);
		expect(options.excludeCredentials).toEqual([
			{ type: "public-key", id: Uint8Array.of(1, 2, 3) },
		]);
		expect(options.authenticatorSelection).toEqual({
			residentKey: "required",
			userVerification: "required",
		});
	});

	it("refuses a creation it did not read", async () => {
		const { creation } = await created();
		expect(await firstKey.createOptions({ ...creation }, { rpName: "Example" })).toEqual({
			error: "statement",
		});
	});

	it("refuses a user handle over 64 bytes", async () => {
		const { creationPayload, sign, mail, options } = await mailed();
		const long = Buffer.alloc(65, 1).toString("base64url");
		const compact = await sign({
			...creationPayload,
			creation: {
				...creationPayload.creation,
				options: { ...creationPayload.creation.options, user_id: long },
			},
		});
		const read = await firstKey.readCreation(compact, mail, options);
		if ("error" in read) throw new Error(read.error);
		expect(await firstKey.createOptions(read.creation, { rpName: "Example" })).toEqual({
			error: "options",
		});
	});

	it("hands on a creation that cannot be changed after it was read", async () => {
		const { creation } = await created();
		expect(Object.isFrozen(creation.statement.creation.options)).toBe(true);
	});
});

describe("firstKey.continuation", () => {
	it("signs the register stage's input with E_sig, ES256's raw r||s", async () => {
		const { creation, creationCompact, keys } = await created();
		const response = '{"id":"AQID"}';
		const signed = await firstKey.continuation(creation, 1, response, keys);
		if ("error" in signed) throw new Error(signed.error);
		const signature = Buffer.from(signed.signature, "base64url");
		expect(signature).toHaveLength(64);
		const input = continuations.of(
			"register",
			await digest(creationCompact),
			1,
			await digest(response),
		);
		const publicKey = await crypto.subtle.importKey(
			"jwk",
			{ ...keys.eSig },
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				publicKey,
				signature,
				utf8(input),
			),
		).toBe(true);
	});

	it("refuses keys other than the ones the creation names", async () => {
		const { creation } = await created();
		expect(await firstKey.continuation(creation, 1, "{}", await screenKeys())).toEqual({
			error: "keys",
		});
	});

	it("refuses a creation it did not read, or a sequence that is no positive integer", async () => {
		const { creation, keys } = await created();
		expect(await firstKey.continuation({ ...creation }, 1, "{}", keys)).toEqual({
			error: "statement",
		});
		for (const seq of [0, -1, 1.5])
			expect(await firstKey.continuation(creation, seq, "{}", keys), String(seq)).toEqual({
				error: "sequence",
			});
	});
});

describe("firstKey.readPossession", () => {
	async function possessed(
		change: Record<string, unknown> = {},
		given?: { alg: number; spki: Uint8Array; jkt: string },
	) {
		const c = await created();
		const key = given ?? (await passkey());
		const payload = {
			v: 1,
			iss: issuer,
			sid: "st-2",
			iat: 1,
			exp: 2,
			e_enc: c.keys.eEnc,
			e_sig: c.keys.eSig,
			nonce: "pn",
			purpose: purposes.possession,
			possession: {
				creation_hash: await digest(c.creationCompact),
				key_jkt: key.jkt,
				credential_id: "BAUG",
				reservation_id: "r-1",
				...change,
			},
		};
		const compact = await c.sign(payload);
		return {
			...c,
			key,
			payload,
			compact,
			credential: { id: "BAUG", spki: key.spki, alg: key.alg },
		};
	}

	it("reads the possession of the screen's own new key, its credential and this creation", async () => {
		const { compact, creation, credential, options, payload } = await possessed();
		const read = await firstKey.readPossession(compact, creation, credential, options);
		expect(read).toMatchObject({ possession: { statement: payload, compact } });
		if ("possession" in read)
			expect(Object.isFrozen(read.possession.statement.possession)).toBe(true);
	});

	it("reads each key of the shared vectors by its SPKI and algorithm to the vector's thumbprint", async () => {
		expect(vectors.map((v) => v.alg).sort()).toEqual([-257, -257, -7, -8]);
		for (const key of vectors) {
			const { compact, creation, credential, options } = await possessed({}, key);
			expect(
				await firstKey.readPossession(compact, creation, credential, options),
				key.name,
			).toHaveProperty("possession");
		}
	});

	it("refuses one naming another creation, another key or another credential", async () => {
		for (const [change, error] of [
			[{ creation_hash: "x".repeat(43) }, "creation"],
			[{ key_jkt: "A".repeat(43) }, "key"],
			[{ credential_id: "AQID" }, "credential"],
		] as const) {
			const { compact, creation, credential, options } = await possessed(change);
			expect(await firstKey.readPossession(compact, creation, credential, options), error).toEqual({
				error,
			});
		}
	});

	it("refuses a new key whose SPKI is not of the algorithm given, or of an algorithm the creation did not offer", async () => {
		const [es, ed] = [vectors.find((v) => v.alg === -7), vectors.find((v) => v.alg === -8)];
		if (!es || !ed) throw new Error("vectors");
		const { compact, creation, options } = await possessed({}, es);
		for (const alg of [-8, -257, -35, 0])
			expect(
				await firstKey.readPossession(
					compact,
					creation,
					{ id: "BAUG", spki: es.spki, alg },
					options,
				),
				String(alg),
			).toEqual({ error: "key" });
		expect(
			await firstKey.readPossession(
				compact,
				creation,
				{ id: "BAUG", spki: ed.spki, alg: -7 },
				options,
			),
		).toEqual({ error: "key" });
		const narrow = await mailed();
		const offered = await narrow.sign({
			...narrow.creationPayload,
			creation: {
				...narrow.creationPayload.creation,
				options: { ...narrow.creationPayload.creation.options, algorithms: [-7] },
			},
		});
		const read = await firstKey.readCreation(offered, narrow.mail, narrow.options);
		if ("error" in read) throw new Error(read.error);
		const possession = await narrow.sign({
			v: 1,
			iss: issuer,
			sid: "st-2",
			iat: 1,
			exp: 2,
			e_enc: narrow.keys.eEnc,
			e_sig: narrow.keys.eSig,
			nonce: "pn",
			purpose: purposes.possession,
			possession: {
				creation_hash: await digest(offered),
				key_jkt: ed.jkt,
				credential_id: "BAUG",
				reservation_id: "r-1",
			},
		});
		expect(
			await firstKey.readPossession(
				possession,
				read.creation,
				{ id: "BAUG", spki: ed.spki, alg: -8 },
				narrow.options,
			),
		).toEqual({ error: "key" });
	});

	it("refuses a SPKI of each algorithm cut short, with bytes after it, or with a length not in its shortest form", async () => {
		/** The SPKI with its outer length written one byte longer than it must be. */
		const longer = (spki: Buffer) => {
			const first = spki[1] ?? 0;
			const head =
				first < 0x80
					? Buffer.of(0x30, 0x81, first)
					: Buffer.concat([Buffer.of(0x30, first + 1, 0), spki.subarray(2, 2 + (first & 0x7f))]);
			return Buffer.concat([head, spki.subarray(first < 0x80 ? 2 : 2 + (first & 0x7f))]);
		};
		for (const key of vectors) {
			const { compact, creation, options } = await possessed({}, key);
			for (const [why, spki] of [
				["none", new Uint8Array()],
				["short", key.spki.subarray(0, -1)],
				["after", Buffer.concat([key.spki, Buffer.of(0)])],
				["longer", longer(key.spki)],
			] as const)
				expect(
					await firstKey.readPossession(
						compact,
						creation,
						{ id: "BAUG", spki, alg: key.alg },
						options,
					),
					`${key.name} ${why}`,
				).toEqual({ error: "key" });
		}
	});

	it("refuses a P-256 point compressed or off the curve, though the possession names that key", async () => {
		const es = vectors.find((v) => v.alg === -7);
		if (!es) throw new Error("vectors");
		const { compact, creation, options } = await possessed({}, es);
		const point = es.spki.subarray(-65);
		const prefix = Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex");
		const compressed = Buffer.concat([
			prefix,
			Buffer.of((point[64] ?? 0) % 2 === 0 ? 2 : 3),
			point.subarray(1, 33),
		]);
		const off = Buffer.from(es.spki);
		off[off.length - 1] = (off[off.length - 1] ?? 0) ^ 1;
		for (const [why, spki] of [
			["compressed", compressed],
			["off", off],
		] as const)
			expect(
				await firstKey.readPossession(compact, creation, { id: "BAUG", spki, alg: -7 }, options),
				why,
			).toEqual({ error: "key" });
	});

	it("refuses an RSA key the protocol does not take, the possession naming its very thumbprint", async () => {
		const made = async (modulusLength: number, exponent: number[]) => {
			const pair = (await crypto.subtle.generateKey(
				{
					name: "RSASSA-PKCS1-v1_5",
					modulusLength,
					publicExponent: Uint8Array.from(exponent),
					hash: "SHA-256",
				},
				true,
				["sign", "verify"],
			)) as CryptoKeyPair;
			const { e, kty, n } = await crypto.subtle.exportKey("jwk", pair.publicKey);
			return {
				alg: -257,
				spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
				jkt: await digest(canonicalText({ e, kty, n })),
			};
		};
		const rs = vectors.find((v) => v.alg === -257);
		if (!rs) throw new Error("vectors");
		// The modulus's last byte sits before the exponent's five bytes (02 03 01 00 01).
		const even = Buffer.from(rs.spki);
		even[even.length - 6] = (even[even.length - 6] ?? 0) & 0xfe;
		for (const [why, key] of [
			["1024 bits", await made(1024, [1, 0, 1])],
			["exponent 3", await made(2048, [3])],
			["even modulus", { alg: -257, spki: even, jkt: rs.jkt }],
		] as const) {
			const { compact, creation, credential, options } = await possessed({}, key);
			expect(await firstKey.readPossession(compact, creation, credential, options), why).toEqual({
				error: "key",
			});
		}
	});

	it("reads the SPKI as getPublicKey() gives it, an ArrayBuffer", async () => {
		const es = vectors.find((v) => v.alg === -7);
		if (!es) throw new Error("vectors");
		const { compact, creation, options } = await possessed({}, es);
		const buffer = new Uint8Array(es.spki).buffer;
		expect(
			await firstKey.readPossession(
				compact,
				creation,
				{ id: "BAUG", spki: buffer, alg: -7 },
				options,
			),
		).toHaveProperty("possession");
	});

	it("asks the new key's get() over the possession, for that credential alone", async () => {
		const { compact, creation, credential, options } = await possessed();
		const read = await firstKey.readPossession(compact, creation, credential, options);
		if ("error" in read) throw new Error(read.error);
		const asked = await firstKey.assertionOptions(read.possession);
		if ("error" in asked) throw new Error(asked.error);
		expect(Buffer.from(asked.options.challenge as Uint8Array).toString("base64url")).toBe(
			await digest(`get\u0000${compact}`),
		);
		expect(asked.options.allowCredentials).toEqual([
			{ type: "public-key", id: Uint8Array.of(4, 5, 6) },
		]);
		expect(asked.options.userVerification).toBe("required");
		expect(asked.options.rpId).toBe("id.example");
		expect(await firstKey.assertionOptions({ ...read.possession })).toEqual({
			error: "statement",
		});
	});
});
