import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { promiseNames, stances } from "@mod/promises";
import { CompactSign, decodeProtectedHeader } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { keys, type Signed } from "../src/contract.ts";
import keysModule from "../src/module.ts";
import { section as keysSection } from "../src/section.ts";
import { keysConfig, testHolder } from "../src/testing.ts";

const january = Date.parse("2026-01-01T00:00:00Z");
let now = january;
afterEach(() => {
	now = january;
});
const runtime = quietRuntime({ clock: { now: () => now } });

const ed25519 = () => generateKeyPairSync("ed25519");
// RSA keys are slow to make: made once, as the file loads, never within a test's time.
const rsa = () => generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaKeys = { a: rsa(), b: rsa(), c: rsa(), d: rsa() };
const bytes = (claims: unknown) => new TextEncoder().encode(JSON.stringify(claims));
const jwsOf = (signed: Signed) => {
	if (signed.kind !== "signed") throw new Error("expected a signature");
	return signed.jws;
};

/** The keys section with these parts in place of the test builder's. */
const sectionWith = (parts: Record<string, unknown>) => ({ ...keysConfig().keys, ...parts });

async function boot(section: unknown, held: Readonly<Record<string, KeyObject>> = {}) {
	const app = await assemble({
		modules: [keysModule, testHolder(held)],
		config: { ...kernelConfig(), keys: section },
		runtime,
	});
	return app.get(keys);
}

async function refusalsAt(section: unknown, held: Readonly<Record<string, KeyObject>> = {}) {
	try {
		await boot(section, held);
	} catch (error) {
		if (error instanceof BootRefused) return error.refusals;
		throw error;
	}
	throw new Error("expected a refusal");
}

const refusedAt = async (section: unknown, held: Readonly<Record<string, KeyObject>> = {}) =>
	(await refusalsAt(section, held)).map((r) => r.where);

/** The token with its header's kid replaced; the signature no longer matches. */
function withKid(token: string, kid: string): string {
	const [h = "", p, s] = token.split(".");
	const header = { ...JSON.parse(Buffer.from(h, "base64url").toString()), kid };
	return [Buffer.from(JSON.stringify(header)).toString("base64url"), p, s].join(".");
}

const base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** The token with the signature's last character changed in a bit decoding drops: the same bytes, another string. */
function withLastBitsFlipped(token: string): string {
	const at = base64url.indexOf(token.at(-1) as string);
	return `${token.slice(0, -1)}${base64url[at ^ 1]}`;
}

/** A token signed as another holder of a key would sign it. */
const signedBy = (key: KeyObject, kid: string, payload: string, typ = "JWT") =>
	new CompactSign(new TextEncoder().encode(payload))
		.setProtectedHeader({ alg: "EdDSA", typ, kid })
		.sign(key);

describe("keys", () => {
	const current = ed25519();
	const old = ed25519();
	const held = { now: current.privateKey, old: old.publicKey };
	const rotated = (more: Record<string, unknown> = {}) =>
		sectionWith({
			authority: {
				signing: { kid: "now", alg: "EdDSA" },
				previous: [{ kid: "old", alg: "EdDSA", "expires-at": "2026-06-01T00:00:00Z" }],
				...more,
			},
		});

	it("signs and verifies with the authority's current key, for the typ it was signed for", async () => {
		const k = await boot(rotated(), held);
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(decodeProtectedHeader(token)).toEqual({ alg: "EdDSA", typ: "JWT", kid: "now" });
		const verified = await k.verify("authority", token, "JWT");
		expect(verified).toEqual({ kind: "valid", claims: { sub: "a" } });
		expect(verified.kind === "valid" && Object.isFrozen(verified.claims)).toBe(true);
		expect(await k.verify("authority", token, "rt+jwt")).toEqual({
			kind: "invalid",
			reason: "typ",
		});
		expect(await k.verify("authority", "not a jws", "JWT")).toEqual({
			kind: "invalid",
			reason: "malformed",
		});
	});

	it("signs the payload's bytes as given, so a caller's canonical form is what is signed", async () => {
		const k = await boot(rotated(), held);
		const payload = new TextEncoder().encode('{"b":1,"a":{"d":2,"c":3}}');
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), payload));
		expect(Buffer.from(token.split(".")[1] as string, "base64url").toString()).toBe(
			'{"b":1,"a":{"d":2,"c":3}}',
		);
	});

	it("refuses to sign a payload that is no JSON object, as the caller's TypeError", async () => {
		const k = await boot(rotated(), held);
		for (const payload of ["{no json", "[1,2]", '"text"', "null"]) {
			await expect(
				k.sign(k.prepare("authority", "JWT"), new TextEncoder().encode(payload)),
				payload,
			).rejects.toThrow(TypeError);
		}
	});

	it("verifies what the previous key signed until it expires, and tells an unknown kid", async () => {
		const k = await boot(rotated(), held);
		const byOld = await signedBy(old.privateKey, "old", JSON.stringify({ sub: "a" }));
		expect(await k.verify("authority", byOld, "JWT")).toEqual({
			kind: "valid",
			claims: { sub: "a" },
		});
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(await k.verify("authority", withKid(token, "nobody"), "JWT")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		expect(await k.verify("authority", withKid(token, "old"), "JWT")).toEqual({
			kind: "invalid",
			reason: "signature",
		});
		now = Date.parse("2026-06-01T00:00:00Z") - 1;
		expect((await k.verify("authority", byOld, "JWT")).kind).toBe("valid");
		now += 1;
		expect(await k.verify("authority", byOld, "JWT")).toEqual({
			kind: "invalid",
			reason: "kid_expired",
		});
	});

	it("verifies with the next key, but never signs with it [oidc-core-10.1-d]", async () => {
		const coming = ed25519();
		const k = await boot(rotated({ next: { kid: "next", alg: "EdDSA" } }), {
			...held,
			next: coming.privateKey,
		});
		const signed = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(decodeProtectedHeader(signed).kid).toBe("now");
		const byNext = await signedBy(coming.privateKey, "next", JSON.stringify({ sub: "a" }));
		expect(await k.verify("authority", byNext, "JWT")).toEqual({
			kind: "valid",
			claims: { sub: "a" },
		});
	});

	it("names the algorithm each ring signs with and the one its next key will, none without one", async () => {
		const coming = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
		const withNext = await boot(
			sectionWith({
				authority: {
					signing: { kid: "now", alg: "EdDSA" },
					next: { kid: "next", alg: "RS256" },
				},
				core: {
					generation: 1,
					keys: [
						{ generation: 1, kid: "core-test", alg: "ES256" },
						{ generation: 2, kid: "core-2", alg: "EdDSA" },
					],
				},
			}),
			{ ...held, next: coming, "core-2": ed25519().publicKey },
		);
		expect([withNext.algorithm("authority"), withNext.nextAlgorithm("authority")]).toEqual([
			"EdDSA",
			"RS256",
		]);
		expect([withNext.algorithm("core"), withNext.nextAlgorithm("core")]).toEqual([
			"ES256",
			"EdDSA",
		]);
		const without = await boot(rotated(), held);
		expect([without.nextAlgorithm("authority"), without.nextAlgorithm("core")]).toEqual([
			undefined,
			undefined,
		]);
	});

	it("signs on the Core's ring with its generation's key, apart from the authority's ring", async () => {
		const earlier = ed25519();
		const k = await boot(
			sectionWith({
				core: {
					generation: 2,
					keys: [
						{ generation: 1, kid: "core-1", alg: "EdDSA" },
						{ generation: 2, kid: "core-test", alg: "ES256" },
						{ generation: 3, kid: "core-3", alg: "ES256" },
					],
				},
			}),
			{
				"core-1": earlier.publicKey,
				"core-3": generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey,
			},
		);
		const statement = jwsOf(
			await k.sign(k.prepare("core", "approval+jwt"), bytes({ purpose: "authorization" })),
		);
		expect(decodeProtectedHeader(statement)).toEqual({
			alg: "ES256",
			typ: "approval+jwt",
			kid: "core-test",
		});
		expect((await k.verify("core", statement, "approval+jwt")).kind).toBe("valid");
		// A ring verifies only by its own keys.
		expect(await k.verify("authority", statement, "approval+jwt")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		expect(await k.verify("core", token, "JWT")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		// What an earlier generation signed verifies only where its generation is named.
		const byEarlier = await signedBy(earlier.privateKey, "core-1", "{}", "approval+jwt");
		expect(await k.verify("core", byEarlier, "approval+jwt")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		expect((await k.verifyOf(1, byEarlier, "approval+jwt")).kind).toBe("valid");
		expect(await k.verifyOf(1, statement, "approval+jwt")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		expect((await k.verifyOf(2, statement, "approval+jwt")).kind).toBe("valid");
		expect(await k.verifyOf(4, statement, "approval+jwt")).toEqual({
			kind: "invalid",
			reason: "kid_unknown",
		});
		expect(k.generation()).toBe(2);
	});

	it("refuses a token whose signature is written in a form other than its one form", async () => {
		const k = await boot(rotated(), held);
		const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
		const variant = withLastBitsFlipped(token);
		expect(variant).not.toBe(token);
		expect(await k.verify("authority", variant, "JWT")).toEqual({
			kind: "invalid",
			reason: "malformed",
		});
	});

	it("answers a payload the key signed that is no JSON as a bad signature", async () => {
		const k = await boot(rotated(), held);
		expect(
			await k.verify("authority", await signedBy(current.privateKey, "now", "{no json"), "JWT"),
		).toEqual({ kind: "invalid", reason: "signature" });
	});

	it("refuses missing, malformed, mismatched, unheld and duplicate keys, and a sealing key that agrees with none", async () => {
		const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const rsa1024 = generateKeyPairSync("rsa", { modulusLength: 1024 });
		const coreKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
		const has = {
			...held,
			p256: p256.privateKey,
			small: rsa1024.privateKey,
			public: current.publicKey,
			ed: current.privateKey,
			again: current.privateKey,
			"core-test": coreKey,
			"core-again": coreKey,
			"p256-again": p256.privateKey,
		};
		const signing = { kid: "now", alg: "EdDSA" };
		const previous = { kid: "old", alg: "EdDSA", "expires-at": "2027-01-01T00:00:00Z" };
		const authority = (more: Record<string, unknown>) =>
			sectionWith({ authority: { signing, ...more } });
		const cases: Record<string, [section: unknown, where: string]> = {
			"no authority ring": [{ ...keysConfig().keys, authority: undefined }, "keys.authority"],
			"no signing key": [sectionWith({ authority: {} }), "keys.authority.signing"],
			"kid with a space": [
				authority({ signing: { ...signing, kid: "bad kid" } }),
				"keys.authority.signing.kid",
			],
			"kid repeated in previous": [
				authority({ previous: [{ ...previous, kid: "now" }] }),
				"keys.authority.previous.0.kid",
			],
			"kid repeated in next": [
				authority({ next: { kid: "now", alg: "EdDSA" } }),
				"keys.authority.next.kid",
			],
			"kid repeated across rings": [
				sectionWith({
					core: { generation: 1, keys: [{ generation: 1, kid: "test", alg: "ES256" }] },
				}),
				"keys.core.keys.0.kid",
			],
			"kid repeated as the sealing key": [
				sectionWith({ sealing: { kid: "test" } }),
				"keys.sealing.kid",
			],
			"Ed25519 key named ES256": [
				authority({ signing: { ...signing, alg: "ES256" } }),
				"keys.authority.signing.kid",
			],
			"P-256 key named EdDSA": [
				authority({ signing: { ...signing, kid: "p256" } }),
				"keys.authority.signing.kid",
			],
			"RSA key under 2048 bits": [
				authority({ signing: { kid: "small", alg: "RS256" } }),
				"keys.authority.signing.kid",
			],
			"RSA key under 2048 bits named PS256": [
				authority({ signing: { kid: "small", alg: "PS256" } }),
				"keys.authority.signing.kid",
			],
			"signing key held as its public half": [
				authority({ signing: { ...signing, kid: "public" } }),
				"keys.authority.signing.kid",
			],
			"signing key not held": [
				authority({ signing: { ...signing, kid: "nobody" } }),
				"keys.authority.signing.kid",
			],
			"next key not held": [
				authority({ next: { kid: "nobody", alg: "EdDSA" } }),
				"keys.authority.next.kid",
			],
			"previous key named ES256": [
				authority({ previous: [{ ...previous, alg: "ES256" }] }),
				"keys.authority.previous.0.kid",
			],
			"sealing key that is no P-256": [sectionWith({ sealing: { kid: "ed" } }), "keys.sealing.kid"],
			"sealing key held as its public half": [
				sectionWith({ sealing: { kid: "old" } }),
				"keys.sealing.kid",
			],
			"current generation unlisted": [
				sectionWith({
					core: { generation: 2, keys: [{ generation: 1, kid: "core-test", alg: "ES256" }] },
				}),
				"keys.core.generation",
			],
			"generation listed twice": [
				sectionWith({
					core: {
						generation: 1,
						keys: [
							{ generation: 1, kid: "core-test", alg: "ES256" },
							{ generation: 1, kid: "p256", alg: "ES256" },
						],
					},
				}),
				"keys.core.keys.1.generation",
			],
			"one key in both rings": [
				sectionWith({
					authority: { signing },
					core: { generation: 1, keys: [{ generation: 1, kid: "again", alg: "EdDSA" }] },
				}),
				"keys.core.keys.0.kid",
			],
			"one key in two generations": [
				sectionWith({
					authority: { signing },
					core: {
						generation: 1,
						keys: [
							{ generation: 1, kid: "core-test", alg: "ES256" },
							{ generation: 2, kid: "core-again", alg: "ES256" },
						],
					},
				}),
				"keys.core.keys.1.kid",
			],
			"one key signing and sealing": [
				sectionWith({
					authority: { signing: { kid: "p256", alg: "ES256" } },
					sealing: { kid: "p256-again" },
				}),
				"keys.sealing.kid",
			],
			"unknown member": [
				authority({ signing: { ...signing, extra: 1 } }),
				"keys.authority.signing",
			],
		};
		for (const [name, [section, where]] of Object.entries(cases)) {
			expect(await refusedAt(section, has), name).toEqual([where]);
		}
	});

	it("says of a key not of its alg's kind which alg it is to match, and of one not held where to hold it", async () => {
		const signing = { kid: "now", alg: "ES256" };
		expect(await refusalsAt(sectionWith({ authority: { signing } }), held)).toEqual([
			{
				where: "keys.authority.signing.kid",
				reason: "the key held for it is not of the kind keys.authority.signing.alg names",
			},
		]);
		expect(
			await refusalsAt(
				sectionWith({ authority: { signing: { kid: "nobody", alg: "EdDSA" } } }),
				held,
			),
		).toEqual([
			{
				where: "keys.authority.signing.kid",
				reason: "no key of this kid is held: hold it in the section of the keys axis's adapter",
			},
		]);
	});

	it("holds no past keys and no next key when the operator writes only the signing key", () => {
		const read = keysSection.parse(keysConfig().keys);
		expect(read.authority).toEqual({ signing: { kid: "test", alg: "ES256" }, previous: [] });
	});

	it("names in alg the RSA or ECDSA algorithm it signs with, and verifies under it [oidc-core-10.1-b]", async () => {
		const pairs = {
			ES256: generateKeyPairSync("ec", { namedCurve: "P-256" }),
			PS256: rsaKeys.a,
			RS256: rsaKeys.b,
		};
		for (const [alg, pair] of Object.entries(pairs)) {
			const k = await boot(sectionWith({ authority: { signing: { kid: "k", alg } } }), {
				k: pair.privateKey,
			});
			const token = jwsOf(await k.sign(k.prepare("authority", "JWT"), bytes({ sub: "a" })));
			expect(decodeProtectedHeader(token), alg).toMatchObject({ alg, kid: "k", typ: "JWT" });
			expect(k.algorithm("authority"), alg).toBe(alg);
			expect((await k.verify("authority", token, "JWT")).kind, alg).toBe("valid");
		}
	});

	it("warns at every start of the ring keys named RS256, by their paths, and of none where none is", async () => {
		const { a: signing, b: previous, c: next, d: later } = rsaKeys;
		const held = {
			r: signing.privateKey,
			o: previous.publicKey,
			n: next.publicKey,
			c2: later.publicKey,
		};
		const warned = async (section: unknown) => {
			const recorded = recordingLog();
			await assemble({
				modules: [keysModule, testHolder(held)],
				config: { ...kernelConfig(), keys: section },
				runtime: quietRuntime({ clock: { now: () => now }, log: recorded.log }),
			});
			return recorded.lines().filter((line) => line.event === "keys.rs256_deprecated");
		};
		const lines = await warned(sectionWith({ authority: { signing: { kid: "r", alg: "RS256" } } }));
		expect(lines.map((line) => [line.level, line.fields.keys])).toEqual([
			["warn", "keys.authority.signing.alg"],
		]);
		expect(lines[0]?.fields.reason).toMatch(/112 bits.*PKCS#1 v1\.5.*FAPI 2\.0/);
		const everyRing = sectionWith({
			authority: {
				signing: { kid: "r", alg: "RS256" },
				previous: [{ kid: "o", alg: "RS256", "expires-at": "2027-01-01T00:00:00Z" }],
				next: { kid: "n", alg: "RS256" },
			},
			core: {
				generation: 1,
				keys: [
					{ generation: 1, kid: "core-test", alg: "ES256" },
					{ generation: 2, kid: "c2", alg: "RS256" },
				],
			},
		});
		expect((await warned(everyRing)).map((line) => line.fields.keys)).toEqual([
			"keys.authority.signing.alg keys.authority.previous.0.alg keys.authority.next.alg keys.core.keys.1.alg",
		]);
		expect(
			await warned(sectionWith({ authority: { signing: { kid: "r", alg: "PS256" } } })),
		).toEqual([]);
		expect(await warned(keysConfig().keys)).toEqual([]);
	});

	it("is taken only by a module that declares where it stands on the promises", async () => {
		const taking = (declares: boolean) =>
			defineModule({ name: "statements", replicaSafe: true, takes: [keys] }, (m) =>
				declares
					? [
							m.contribute(stances).by(() => ({
								promise: promiseNames.newAuthorization,
								holds: true,
								by: "statements",
							})),
						]
					: [],
			);
		const config = { ...kernelConfig(), ...keysConfig() };
		const refused = await assemble({
			modules: [keysModule, testHolder(), taking(false)],
			config,
			runtime,
		}).catch((error: unknown) => error);
		expect((refused as BootRefused).refusals).toEqual([
			{
				where: "statements",
				reason: "keys is taken only by a module that contributes to promises.stances",
			},
		]);
		await expect(
			assemble({ modules: [keysModule, testHolder(), taking(true)], config, runtime }),
		).resolves.toBeDefined();
	});
});
