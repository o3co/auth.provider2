import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { algorithmNames, ceremoniesFor, challengeOf } from "../src/ceremony/ceremony.ts";
import type { Credential, Verification } from "../src/contract.ts";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
} from "../src/testing.ts";

const rp = {
	id: "rp.example",
	name: "RP",
	origins: [testOrigin],
	topOrigins: ["https://shell.example"],
	algorithms: algorithmNames,
};
const ceremonies = ceremoniesFor(rp);
const handle = randomBytes(32).toString("base64url");
const at = { origin: testOrigin };
const evil = { origin: "https://evil.example" };

/** A challenge as a caller gives one: 32 bytes, unpadded base64url. */
const fresh = () => randomBytes(32).toString("base64url");

/** Creation options for `handle` over a fresh challenge, as the browser receives them, and that challenge. */
function creation(v: Verification = "preferred", c = ceremonies) {
	const challenge = fresh();
	const options = c.creation(challenge, { handle, name: "sam" }, [], v);
	return { options: options as CreationOptions, challenge };
}

/** Request options listing no credential over a fresh challenge, as the browser receives them, and that challenge. */
function request(v: Verification = "preferred") {
	const challenge = fresh();
	return { options: ceremonies.request(challenge, [], v) as RequestOptions, challenge };
}

/** A credential made by `authenticator`, as attested. */
async function made(authenticator = softwareAuthenticator()) {
	const { options, challenge } = creation();
	const attested = await ceremonies.attest(
		authenticator.create(options, at),
		challenge,
		handle,
		"preferred",
	);
	if (attested.kind !== "attested") throw new Error(attested.reason);
	return { authenticator, credential: attested.credential };
}

const reasonOf = (answer: { kind: string; reason?: string }) => answer.reason ?? answer.kind;

describe("the challenge the caller gives", () => {
	it("is the one the options ask to sign, as given, and the same one twice asks the same", () => {
		const challenge = fresh();
		const created = ceremonies.creation(challenge, { handle, name: "sam" }, []);
		const requested = ceremonies.request(challenge, []);
		expect(created).toMatchObject({ challenge });
		expect(requested).toMatchObject({ challenge });
		expect(ceremonies.request(challenge, [])).toEqual(requested);
	});

	it("is refused, before anything is asked or read, unless it is 32 bytes of unpadded base64url", async () => {
		const { authenticator, credential } = await made();
		const asked = request();
		const response = authenticator.get(asked.options, at);
		const others: Record<string, unknown> = {
			"31 bytes": randomBytes(31).toString("base64url"),
			"33 bytes": randomBytes(33).toString("base64url"),
			padded: `${fresh()}=`,
			"standard base64": Buffer.alloc(32, 0xfb).toString("base64"),
			// 32 zero bytes, spelt with the bits past them set.
			"another spelling of the same bytes": `${"A".repeat(42)}B`,
			empty: "",
			"not a string": 5,
		};
		for (const [name, challenge] of Object.entries(others)) {
			const given = challenge as string;
			expect(() => ceremonies.creation(given, { handle, name: "sam" }, []), name).toThrow(
				TypeError,
			);
			expect(() => ceremonies.request(given, []), name).toThrow(TypeError);
			await expect(ceremonies.attest(response, given, handle), name).rejects.toThrow(TypeError);
			await expect(
				ceremonies.assert(response, { challenge: given, named: false }, credential),
				name,
			).rejects.toThrow(TypeError);
		}
	});

	it("refuses, at attest and at assert alike, client data answering another spelling or length of it, or it with an ending", async () => {
		const { authenticator, credential } = await made();
		const challenge = `${"A".repeat(42)}A`;
		const variants: Record<string, string> = {
			padded: `${challenge}=`,
			"a tail of the same bytes": `${"A".repeat(42)}B`,
			"31 bytes": "A".repeat(42),
			"33 bytes": "A".repeat(44),
			"the named ending": `${challenge}.listed`,
		};
		for (const [name, answered] of Object.entries(variants)) {
			const created = ceremonies.creation(challenge, { handle, name: "sam" }, [], "preferred");
			const response = softwareAuthenticator().create(
				{ ...(created as CreationOptions), challenge: answered },
				at,
			);
			expect(
				reasonOf(await ceremonies.attest(response, challenge, handle, "preferred")),
				name,
			).toBe("challenge");
			const requested = ceremonies.request(challenge, [], "preferred") as RequestOptions;
			const got = authenticator.get({ ...requested, challenge: answered }, at);
			for (const named of [false, true]) {
				const asserted = await ceremonies.assert(
					got,
					{ challenge, named },
					credential,
					"preferred",
				);
				expect(reasonOf(asserted), name).toBe("challenge");
			}
		}
	});

	it("is judged by no lifetime: an answer however late passes, and the options name no timeout", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request();
		expect(options).not.toHaveProperty("timeout");
		expect(creation().options).not.toHaveProperty("timeout");
		const asserted = await ceremonies.assert(
			authenticator.get(options, at),
			{ challenge, named: false },
			credential,
			"preferred",
		);
		expect(reasonOf(asserted)).toBe("asserted");
	});
});

describe("creation and attestation", () => {
	it("offers the challenge, the three algorithms, the subject's credentials to exclude, and asks for a discoverable credential", () => {
		const challenge = fresh();
		const options = ceremonies.creation(challenge, { handle, name: "sam" }, ["AAAA"], "required");
		expect(options).toMatchObject({
			rp: { id: "rp.example", name: "RP" },
			user: { id: handle, name: "sam" },
			challenge,
			pubKeyCredParams: [-8, -7, -257].map((alg) => ({ alg, type: "public-key" })),
			excludeCredentials: [{ id: "AAAA", type: "public-key" }],
			authenticatorSelection: {
				residentKey: "required",
				requireResidentKey: true,
				userVerification: "required",
			},
		});
	});

	it("asks for a credential that need not be discoverable when told", async () => {
		const options = ceremonies.creation(fresh(), { handle, name: "sam" }, [], "preferred", {
			discoverable: false,
		});
		expect(options).toMatchObject({
			authenticatorSelection: {
				residentKey: "discouraged",
				requireResidentKey: false,
				userVerification: "preferred",
			},
		});
	});

	it("requires user verification where none is asked, in the options and of the answer", async () => {
		const challenge = fresh();
		const options = ceremonies.creation(challenge, { handle, name: "sam" }, []);
		expect(options).toMatchObject({ authenticatorSelection: { userVerification: "required" } });
		const unverified = softwareAuthenticator({ userVerified: false }).create(
			options as CreationOptions,
			at,
			{ overlook: true },
		);
		expect(reasonOf(await ceremonies.attest(unverified, challenge, handle))).toBe(
			"user-verification",
		);
	});

	it("weakens user verification only where preferred or discouraged is asked; any other value asks it", async () => {
		for (const v of [null, "Preferred", "none", 0] as unknown as Verification[]) {
			const challenge = fresh();
			const options = ceremonies.creation(challenge, { handle, name: "sam" }, [], v);
			expect(options, String(v)).toMatchObject({
				authenticatorSelection: { userVerification: "required" },
			});
			expect(ceremonies.request(challenge, [], v), String(v)).toMatchObject({
				userVerification: "required",
			});
			const unverified = softwareAuthenticator({ userVerified: false }).create(
				options as CreationOptions,
				at,
				{ overlook: true },
			);
			expect(reasonOf(await ceremonies.attest(unverified, challenge, handle, v)), String(v)).toBe(
				"user-verification",
			);
		}
		const { authenticator, credential } = await made(
			softwareAuthenticator({ userVerified: false }),
		);
		for (const v of [null, "Preferred"] as unknown as Verification[]) {
			const { options, challenge } = request();
			const response = authenticator.get(options, at, { overlook: true });
			const asserted = await ceremonies.assert(
				response,
				{ challenge, named: false },
				credential,
				v,
			);
			expect(reasonOf(asserted), String(v)).toBe("user-verification");
		}
	});

	it("attests a credential for the handle, keeping its key, count and backup eligibility", async () => {
		const { credential } = await made(softwareAuthenticator({ backupEligible: true }));
		expect(credential).toMatchObject({
			signCount: 0,
			userHandle: handle,
			backupEligible: true,
			backedUp: true,
			transports: ["internal"],
		});
		expect(Buffer.from(credential.id, "base64url").toString("base64url")).toBe(credential.id);
	});

	it("keeps the transports the client lists only as a short list of short strings, else none", async () => {
		const cases: Record<string, unknown> = {
			"an object": {},
			"a number": 5,
			"one string": "usb",
			"a list with a number": ["usb", 1],
			"nine of them": Array(9).fill("usb"),
			"one too long": ["u".repeat(33)],
		};
		for (const [name, transports] of Object.entries(cases)) {
			const { options, challenge } = creation();
			const response = softwareAuthenticator().create(options, at);
			(response as { response: { transports?: unknown } }).response.transports = transports;
			const attested = await ceremonies.attest(response, challenge, handle, "preferred");
			expect(attested, name).toMatchObject({ kind: "attested" });
			expect((attested as { credential: object }).credential, name).not.toHaveProperty(
				"transports",
			);
		}
	});

	it("attests a credential id longer than 255 bytes", async () => {
		const { options, challenge } = creation();
		const credentialId = randomBytes(300).toString("base64url");
		const response = softwareAuthenticator().create(options, at, { credentialId });
		const attested = await ceremonies.attest(response, challenge, handle, "preferred");
		expect(attested).toMatchObject({ kind: "attested", credential: { id: credentialId } });
	});

	it("refuses another origin, challenge, relying party, algorithm, and an unverified user when required", async () => {
		const { options, challenge } = creation("required");
		// Each of these a browser would stop; only a client that overlooks it sends one.
		const overlook = { overlook: true };
		const attest = (
			response: unknown,
			v: "required" | "preferred" = "preferred",
			expected = challenge,
		) => ceremonies.attest(response, expected, handle, v).then(reasonOf);
		const plain = softwareAuthenticator();
		expect(await attest(plain.create(options, evil, overlook))).toBe("origin");
		expect(await attest(plain.create(options, at), "preferred", fresh())).toBe("challenge");
		expect(await attest(plain.create(options, at, { rpId: "evil.example" }))).toBe("rp");
		const es384 = softwareAuthenticator({ algorithm: "ES384" });
		expect(await attest(es384.create(options, at, overlook))).toBe("algorithm");
		const unverified = softwareAuthenticator({ userVerified: false });
		expect(await attest(unverified.create(options, at, overlook), "required")).toBe(
			"user-verification",
		);
	});

	it("attests an unverified user unless verification is required", async () => {
		const { options, challenge } = creation();
		const response = softwareAuthenticator({ userVerified: false }).create(options, at);
		const attested = await ceremonies.attest(response, challenge, handle, "preferred");
		expect(reasonOf(attested)).toBe("attested");
	});

	it("refuses a response whose client data cannot be read", async () => {
		const { challenge } = creation();
		for (const response of [{ response: { clientDataJSON: 5 } }, "not a response"]) {
			const attested = await ceremonies.attest(response, challenge, handle, "preferred");
			expect(reasonOf(attested)).toBe("malformed");
		}
	});

	it("refuses a framed ceremony from a page not listed, or one that says it is not framed", async () => {
		const { options, challenge } = creation();
		const a = softwareAuthenticator();
		// A browser never says a page is not framed while naming its top origin.
		const framed = (topOrigin: string, crossOrigin = true) =>
			ceremonies
				.attest(
					a.create(options, { ...at, crossOrigin, topOrigin }, { overlook: !crossOrigin }),
					challenge,
					handle,
					"preferred",
				)
				.then(reasonOf);
		expect(await framed("https://evil.example")).toBe("top-origin");
		expect(await framed("https://shell.example", false)).toBe("top-origin");
		expect(await framed("https://shell.example")).toBe("attested");
	});

	it("refuses any framed ceremony when no page may frame one, whether or not a top origin is reported", async () => {
		const unframed = ceremoniesFor({ ...rp, topOrigins: [] });
		const a = softwareAuthenticator();
		for (const client of [
			{ ...at, crossOrigin: true },
			{ ...at, crossOrigin: true, topOrigin: "https://shell.example" },
		]) {
			const { options, challenge } = creation("preferred", unframed);
			const attested = await unframed.attest(
				a.create(options, client),
				challenge,
				handle,
				"preferred",
			);
			expect(reasonOf(attested)).toBe("top-origin");
			const { authenticator, credential } = await made();
			const asserted = await unframed.assert(
				authenticator.get({ challenge, rpId: "rp.example" }, client),
				{ challenge, named: false },
				credential,
				"preferred",
			);
			expect(reasonOf(asserted)).toBe("top-origin");
		}
	});

	it("leaves a frame whose page is not reported to the list of pages that may frame one", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request();
		const framed = { ...at, crossOrigin: true };
		const asserted = await ceremonies.assert(
			authenticator.get(options, framed),
			{ challenge, named: false },
			credential,
			"preferred",
		);
		expect(reasonOf(asserted)).toBe("asserted");
	});

	it("reads the challenge as the library verifies it, never as another decoder would", async () => {
		/** Client data for `challenge` with one 'A' of its base64url made '/', which the library reads as 'A' and a lenient decoder as 63, reading another challenge; none where no 'A' does. */
		const twistOf = (challenge: string) => {
			const json = JSON.stringify({
				type: "webauthn.create",
				challenge,
				origin: testOrigin,
				crossOrigin: false,
			});
			const plain = Buffer.from(json).toString("base64url");
			for (const [i, char] of [...plain].entries()) {
				if (char !== "A") continue;
				const text = `${plain.slice(0, i)}/${plain.slice(i + 1)}`;
				try {
					const read = JSON.parse(Buffer.from(text, "base64url").toString()).challenge;
					if (typeof read === "string" && read !== challenge) return text;
				} catch {}
			}
			return undefined;
		};
		// The first of a fixed run of challenges that has such a twist.
		const found = Array.from({ length: 2000 }, (_, i) =>
			createHash("sha256").update(String(i)).digest("base64url"),
		)
			.map((challenge) => ({ challenge, twist: twistOf(challenge) }))
			.find((c) => c.twist !== undefined);
		if (!found?.twist) throw new Error("no challenge read otherwise");
		const { challenge, twist } = found;
		const response = softwareAuthenticator().create({ ...creation().options, challenge }, at, {
			clientDataJSON: () => twist,
		});
		expect(challengeOf(response)).toBe(challenge);
		expect(reasonOf(await ceremonies.attest(response, challenge, handle, "preferred"))).toBe(
			"attested",
		);
	});
});

describe("request and assertion", () => {
	const assert = (
		response: unknown,
		challenge: string,
		credential: Credential,
		v: "required" | "preferred" = "preferred",
		named = false,
	) => ceremonies.assert(response, { challenge, named }, credential, v);

	it("asks for any of the allowed credentials over the challenge as given, and asserts one, moving its count on", async () => {
		const { authenticator, credential } = await made();
		const challenge = fresh();
		const options = ceremonies.request(challenge, [credential], "preferred");
		expect(options).toMatchObject({
			challenge,
			rpId: "rp.example",
			allowCredentials: [{ id: credential.id, type: "public-key", transports: ["internal"] }],
		});
		const response = authenticator.get(options as RequestOptions, at);
		const asserted = await assert(response, challenge, credential, "preferred", true);
		expect(asserted).toEqual({
			kind: "asserted",
			credential: { ...credential, signCount: 1 },
			userVerified: true,
		});
	});

	it("requires user verification where none is asked, in the options and of the answer", async () => {
		const { credential } = await made();
		const unverified = await made(softwareAuthenticator({ userVerified: false }));
		const challenge = fresh();
		expect(ceremonies.request(challenge, [credential])).toMatchObject({
			userVerification: "required",
		});
		const options = ceremonies.request(challenge, []) as RequestOptions;
		const response = unverified.authenticator.get(options, at, { overlook: true });
		const asserted = await ceremonies.assert(
			response,
			{ challenge, named: false },
			unverified.credential,
		);
		expect(reasonOf(asserted)).toBe("user-verification");
	});

	it("judges the count only once the signature verified, and lets 0 follow 0", async () => {
		const { authenticator, credential } = await made();
		const { credential: other } = await made();
		const { options, challenge } = request();
		const regressed = { ...credential, signCount: 9 };
		const forged = { ...regressed, publicKey: other.publicKey };
		expect(reasonOf(await assert(authenticator.get(options, at), challenge, forged))).toBe(
			"signature",
		);
		expect(reasonOf(await assert(authenticator.get(options, at), challenge, regressed))).toBe(
			"sign-count",
		);
		const countless = await made(softwareAuthenticator({ countless: true }));
		const first = await assert(
			countless.authenticator.get(options, at),
			challenge,
			countless.credential,
		);
		expect(first).toMatchObject({ kind: "asserted", credential: { signCount: 0 } });
		// A count that stayed where it was, and 0 after a count, did not go up.
		const fresher = await made();
		const same = { ...fresher.credential, signCount: 1 };
		expect(reasonOf(await assert(fresher.authenticator.get(options, at), challenge, same))).toBe(
			"sign-count",
		);
		const later = { ...countless.credential, signCount: 5 };
		expect(reasonOf(await assert(countless.authenticator.get(options, at), challenge, later))).toBe(
			"sign-count",
		);
	});

	it("asserts without a handle only where the caller says its request named the credential", async () => {
		const { authenticator, credential } = await made();
		const challenge = fresh();
		const listed = ceremonies.request(challenge, [credential], "preferred") as RequestOptions;
		const left = authenticator.get(listed, at, { userHandle: null });
		expect(reasonOf(await assert(left, challenge, credential, "preferred", true))).toBe("asserted");
		// Said to have named none, the handle is what ties the key to its holder, whatever was listed.
		expect(reasonOf(await assert(left, challenge, credential, "preferred", false))).toBe(
			"user-handle",
		);
		const unnamed = request();
		const bare = authenticator.get(unnamed.options, at, { userHandle: null });
		expect(reasonOf(await assert(bare, unnamed.challenge, credential))).toBe("user-handle");
		// A handle sent as JSON null is none carried.
		const nulled = (got: unknown) => {
			const answered = got as { response: Record<string, unknown> };
			return { ...answered, response: { ...answered.response, userHandle: null } };
		};
		const sent = nulled(authenticator.get(listed, at));
		expect(reasonOf(await assert(sent, challenge, credential, "preferred", true))).toBe("asserted");
		const again = request();
		expect(
			reasonOf(
				await assert(nulled(authenticator.get(again.options, at)), again.challenge, credential),
			),
		).toBe("user-handle");
	});

	it("takes only true as named: a truthy value of another kind asks for the handle", async () => {
		const { authenticator, credential } = await made();
		const challenge = fresh();
		const listed = ceremonies.request(challenge, [credential], "preferred") as RequestOptions;
		const left = authenticator.get(listed, at, { userHandle: null });
		for (const named of ["false", 1, [credential], {}] as unknown as boolean[]) {
			const asserted = await ceremonies.assert(left, { challenge, named }, credential, "preferred");
			expect(reasonOf(asserted), JSON.stringify(named)).toBe("user-handle");
		}
	});

	it("refuses another handle, a changed backup eligibility, and an unverified user when required", async () => {
		const { authenticator, credential } = await made();
		const { options, challenge } = request("required");
		const get = (twist = {}) => authenticator.get(options, at, twist);
		expect(reasonOf(await assert(get({ userHandle: "other" }), challenge, credential))).toBe(
			"user-handle",
		);
		// Named, a handle carried must still be the credential's.
		expect(
			reasonOf(
				await assert(get({ userHandle: "other" }), challenge, credential, "preferred", true),
			),
		).toBe("user-handle");
		const eligible = { ...credential, backupEligible: true };
		expect(reasonOf(await assert(get(), challenge, eligible))).toBe("backup-eligibility");
		const unverified = await made(softwareAuthenticator({ userVerified: false }));
		const response = unverified.authenticator.get(options, at, { overlook: true });
		expect(reasonOf(await assert(response, challenge, unverified.credential, "required"))).toBe(
			"user-verification",
		);
	});

	it("refuses another origin, relying party, challenge, credential, or a frame not listed", async () => {
		const { authenticator, credential } = await made();
		const { credential: other } = await made();
		const { options, challenge } = request();
		const judge = (response: unknown, expected = challenge, by = credential) =>
			assert(response, expected, by).then(reasonOf);
		expect(await judge(authenticator.get(options, evil, { overlook: true }))).toBe("origin");
		expect(await judge(authenticator.get(options, at, { rpId: "evil.example" }))).toBe("rp");
		expect(await judge(authenticator.get(options, at), fresh())).toBe("challenge");
		expect(await judge(authenticator.get(options, at), challenge, other)).toBe("malformed");
		const framed = { ...at, crossOrigin: true, topOrigin: "https://evil.example" };
		expect(await judge(authenticator.get(options, framed))).toBe("top-origin");
		const listed = { ...at, crossOrigin: true, topOrigin: "https://shell.example" };
		expect(await judge(authenticator.get(options, listed))).toBe("asserted");
	});
});

describe("the algorithms the relying party takes", () => {
	/** The ceremonies of a relying party taking these algorithms alone. */
	const taking = (...algorithms: (typeof algorithmNames)[number][]) =>
		ceremoniesFor({ ...rp, algorithms });
	/** A credential a relying party taking these algorithms attests, or its refusal. */
	async function attestedBy(c: ReturnType<typeof taking>, overlook = false) {
		const { options, challenge } = creation("preferred", c);
		const response = softwareAuthenticator().create(options, at, { overlook });
		return c.attest(response, challenge, handle, "preferred");
	}
	/** The credential asserted at a relying party taking these algorithms, or its refusal. */
	async function assertedBy(c: ReturnType<typeof taking>) {
		const { authenticator, credential } = await made();
		const challenge = fresh();
		const options = c.request(challenge, [credential], "preferred");
		return c.assert(
			authenticator.get(options as RequestOptions, at),
			{ challenge, named: true },
			credential,
			"preferred",
		);
	}

	it("offers the algorithms it takes, in their order, and only those", () => {
		const offered = (c: ReturnType<typeof taking>) =>
			(creation("preferred", c).options.pubKeyCredParams ?? []).map((p) => p.alg);
		expect(offered(ceremonies)).toEqual([-8, -7, -257]);
		expect(offered(taking("ES256"))).toEqual([-7]);
		expect(offered(taking("RS256", "ES256"))).toEqual([-257, -7]);
	});

	it("registers and asserts a credential of the one algorithm it takes", async () => {
		const es256 = taking("ES256");
		expect(await attestedBy(es256)).toMatchObject({ kind: "attested" });
		expect(await assertedBy(es256)).toMatchObject({ kind: "asserted" });
	});

	it("registers no credential of an algorithm it does not take: the browser finds none offered, and a client that overlooks it is refused", async () => {
		const eddsa = taking("EdDSA");
		await expect(attestedBy(eddsa)).rejects.toMatchObject({ name: "NotSupportedError" });
		expect(reasonOf(await attestedBy(eddsa, true))).toBe("algorithm");
	});

	it("refuses an assertion by a credential registered with an algorithm it no longer takes", async () => {
		expect(reasonOf(await assertedBy(taking("EdDSA", "RS256")))).toBe("algorithm");
	});
});
